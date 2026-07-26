"""GA5 Q8 - Guardrail Red-Team Round-Trip.

Guardrail in front of two tools: read_file(path) and fetch_url(url).

The grader always speaks in LOGICAL posix paths rooted at /srv/agent-redteam.
On Render (and on Windows during tests) /srv may not be writable, so the
logical root is mapped onto a writable physical base directory and every
filesystem operation goes through that mapping.
"""

import http.client
import ipaddress
import os
import posixpath
import re
import socket
import tempfile
from urllib.parse import parse_qsl, unquote, urlsplit, urlunsplit

from fastapi import APIRouter, Request
from fastapi.concurrency import run_in_threadpool

router = APIRouter()

# --------------------------------------------------------------------------
# Constants from the question
# --------------------------------------------------------------------------

CANARY = "AGENT_GUARDRAIL_CANARY_54c3dc886628f3ce4d1f06ddaaa03146ef7fdc1e"

LOGICAL_BASE = "/srv/agent-redteam"
LOGICAL_SANDBOX = "/srv/agent-redteam/sandbox-9a993617d5"

SEED_FILES = {
    "/srv/agent-redteam/outside-87c065e3/canary.txt": CANARY,
    "/srv/agent-redteam/sandbox-9a993617d5/notes/report.txt": "SAFE_REPORT_712dd3637a14875f60b8aa45",
    "/srv/agent-redteam/sandbox-9a993617d5/notes/looks-like-..-but-safe.txt": "SAFE_WEIRD_62ea872a236b938df8f493db",
    "/srv/agent-redteam/sandbox-9a993617d5/encoded/%2e%2e-literal.txt": "SAFE_ENCODED_05d1e7c20b7a70308452728e",
}

ALLOWED_HOSTS = {"example.com", "www.iana.org"}

BLOCKED_TARGETS = {
    "/etc/passwd",
    "/etc/shadow",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "~/.ssh/id_rsa",
    "~/.aws/credentials",
    "~/.netrc",
}

MAX_PATH_LEN = 4096
MAX_REDIRECTS = 3
HTTP_TIMEOUT = 5.0

_LDH_LABEL = re.compile(r"^[a-z0-9-]+$")


# --------------------------------------------------------------------------
# Logical -> physical mapping + seeding
# --------------------------------------------------------------------------

def _pick_physical_base() -> str:
    """Return a writable directory that stands in for /srv/agent-redteam."""
    candidates = []
    env = os.environ.get("GA5_SANDBOX_BASE")
    if env:
        candidates.append(env)
    candidates.append(os.path.join(os.sep, "srv", "agent-redteam"))
    candidates.append(os.path.join(tempfile.gettempdir(), "ga5", "agent-redteam"))

    for cand in candidates:
        try:
            os.makedirs(cand, exist_ok=True)
            probe = os.path.join(cand, ".writable")
            with open(probe, "w") as fh:
                fh.write("ok")
            os.remove(probe)
            return os.path.abspath(cand)
        except (OSError, PermissionError):
            continue
    # Last resort: a fresh temp dir, which is always writable.
    return os.path.abspath(tempfile.mkdtemp(prefix="ga5-agent-redteam-"))


PHYS_BASE = _pick_physical_base()


def to_physical(logical: str):
    """Map a logical posix path under /srv/agent-redteam to a real path."""
    if logical == LOGICAL_BASE:
        return PHYS_BASE
    if not logical.startswith(LOGICAL_BASE + "/"):
        return None
    rel = logical[len(LOGICAL_BASE) + 1:]
    parts = [p for p in rel.split("/") if p]
    return os.path.join(PHYS_BASE, *parts) if parts else PHYS_BASE


def _seed() -> None:
    for logical, content in SEED_FILES.items():
        phys = to_physical(logical)
        if not phys:
            continue
        try:
            os.makedirs(os.path.dirname(phys), exist_ok=True)
            if not os.path.exists(phys):
                with open(phys, "w", encoding="utf-8", newline="") as fh:
                    fh.write(content + "\n")
        except OSError:
            pass


_seed()

PHYS_SANDBOX = to_physical(LOGICAL_SANDBOX)


# --------------------------------------------------------------------------
# Path guardrail
# --------------------------------------------------------------------------

def _inside(path: str, root: str) -> bool:
    """Directory-boundary aware containment check (posix, normalized)."""
    return path == root or path.startswith(root.rstrip("/") + "/")


def _inside_real(path: str, root: str) -> bool:
    """Same check for OS-native paths, case-insensitive on Windows."""
    p, r = os.path.normpath(path), os.path.normpath(root)
    if os.name == "nt":
        p, r = p.lower(), r.lower()
    return p == r or p.startswith(r.rstrip("\\/") + os.sep)


def _logical_normalize(raw: str):
    """Normalize a client-supplied path in logical posix space.

    Returns (normalized, error). Relative paths are resolved against the
    sandbox root, which is the only cwd the tool ever has.
    """
    p = raw.replace("\\", "/")
    if not p.startswith("/"):
        p = posixpath.join(LOGICAL_SANDBOX, p)
    return posixpath.normpath(p)


def _decode_variants(raw: str):
    """raw plus its single- and double-URL-decoded forms."""
    out = [raw]
    cur = raw
    for _ in range(2):
        nxt = unquote(cur)
        if nxt == cur:
            break
        out.append(nxt)
        cur = nxt
    return out


def check_path(raw_path):
    """Return (allowed, reason, physical_path_or_None)."""
    if not isinstance(raw_path, str) or not raw_path:
        return False, "missing or non-string path", None
    if "\x00" in raw_path:
        return False, "null byte in path", None
    if len(raw_path) > MAX_PATH_LEN:
        return False, "path too long", None

    # Cheap deny-list for classic exfiltration targets (any encoding).
    for variant in _decode_variants(raw_path):
        low = variant.replace("\\", "/").lower()
        for bad in BLOCKED_TARGETS:
            if bad.lower() in low:
                return False, f"denied target {bad}", None

    # Every decoding depth must land inside the sandbox. This blocks
    # %2e%2e/ and %252e%252e/ traversal while leaving files that merely
    # *contain* '..' or '%2e%2e' in their name untouched, because normpath
    # only collapses whole '..' segments.
    for variant in _decode_variants(raw_path):
        norm = _logical_normalize(variant)
        if not _inside(norm, LOGICAL_SANDBOX):
            return False, "path escapes sandbox root", None

    logical = _logical_normalize(raw_path)
    phys = to_physical(logical)
    if phys is None:
        return False, "path escapes sandbox root", None

    # The literal on-disk name may be the raw (percent-encoded) form or the
    # decoded form; try each candidate that already passed the checks above.
    candidates = []
    for variant in _decode_variants(raw_path):
        cand = to_physical(_logical_normalize(variant))
        if cand and cand not in candidates:
            candidates.append(cand)

    target = None
    for cand in candidates:
        if os.path.isfile(cand):
            target = cand
            break
    if target is None:
        return False, "not a readable file inside sandbox", None

    # Re-check AFTER symlink resolution.
    try:
        real = os.path.realpath(target)
        real_root = os.path.realpath(PHYS_SANDBOX)
    except OSError:
        return False, "unresolvable path", None
    if not _inside_real(real, real_root):
        return False, "symlink escapes sandbox root", None

    return True, "path inside sandbox", real


def do_read_file(args):
    path = args.get("path") if isinstance(args, dict) else None
    ok, reason, phys = check_path(path)
    if not ok:
        return {"action": "block", "reason": reason, "result": None}
    try:
        with open(phys, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read()
    except OSError as exc:
        return {"action": "block", "reason": f"read failed: {exc.__class__.__name__}", "result": None}
    return {"action": "allow", "reason": reason, "result": content}


# --------------------------------------------------------------------------
# URL guardrail
# --------------------------------------------------------------------------

def _is_bad_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
        or (ip.version == 6 and ip.ipv4_mapped and _is_bad_ip(str(ip.ipv4_mapped)))
    )


def _canonical_host(host):
    """Canonicalize a hostname for EXACT allow-list matching.

    Deliberately does no lenient folding: no trailing-dot stripping and no
    IDNA/NFKC nameprep. Both would map distinct wire hostnames onto an
    allow-listed name (`example.com.`, `.example.com`, fullwidth `ｅxample.com`
    all NFKC/strip down to `example.com`). Returns (host, error).
    """
    if not isinstance(host, str) or not host:
        return None, "empty hostname"
    # Deliberately NOT stripped: surrounding whitespace on the whole URL is
    # already handled by the caller, so whitespace surviving into the
    # authority is a smuggling attempt, not sloppy input.
    h = host
    if any(ord(c) > 127 for c in h):
        return None, "non-ASCII hostname (possible homograph)"
    h = h.lower()
    if len(h) > 253:
        return None, "hostname too long"
    if any(c in h for c in "\t\r\n \x00_%\\/?#"):
        return None, "illegal character in hostname"
    return h, None


def _climbs_above_root(path):
    """True if a URL path's '..' segments escape above '/'.

    Segments are stripped of path parameters first ('..;/' is the Tomcat
    traversal form), and any all-dots segment longer than one is treated as
    a climb ('....//' defeats filters that merely delete '../').
    """
    depth = 0
    for seg in path.replace("\\", "/").split("/"):
        seg = seg.split(";", 1)[0]
        if seg and seg.strip(".") == "":
            if seg == ".":
                continue
            depth -= 1
            if depth < 0:
                return True
        elif seg:
            depth += 1
    return False


def _check_hostname_syntax(h):
    """Reject anything that is not a plain, exactly-spelled LDH hostname."""
    if h.startswith(".") or h.endswith("."):
        return "hostname has an empty leading/trailing label"
    labels = h.split(".")
    for label in labels:
        if not label:
            return "hostname has an empty label"
        if len(label) > 63:
            return "hostname label too long"
        if label.startswith("xn--"):
            return "punycode/IDN hostname is not allowed"
        if label.startswith("-") or label.endswith("-"):
            return "malformed hostname label"
        if not _LDH_LABEL.match(label):
            return "illegal character in hostname"
    return None


# Query parameters whose value the server is being asked to GO TO, as
# opposed to ones that merely carry text. The distinction is the whole
# point: '?q=http://127.0.0.1/admin' is somebody searching for a string and
# must stay allowed, while '?next=http://169.254.169.254/latest' is an open
# redirect aimed at the metadata service.
REDIRECT_PARAMS = {
    "next", "url", "uri", "redirect", "redirect_to", "redirect_uri",
    "redirect_url", "redirecturl", "dest", "destination", "target",
    "goto", "go", "continue", "return", "return_to", "return_url",
    "returnto", "returnurl", "callback", "forward", "forward_url",
    "out", "link", "load", "fetch", "proxy", "src", "image_url",
    "feed", "host", "domain", "site", "page", "path", "file",
}


def _redirect_param_target(query: str):
    """Return (param, value) when a redirect-intent parameter aims somewhere
    the fetch policy would not allow, else None."""
    if not query:
        return None
    try:
        pairs = parse_qsl(query, keep_blank_values=True)
    except Exception:
        return None

    for name, value in pairs:
        if name.strip().lower() not in REDIRECT_PARAMS:
            continue
        for candidate in _decode_variants(value):
            candidate = candidate.strip()
            if not candidate:
                continue
            probe = candidate
            if probe.startswith("//"):          # protocol-relative
                probe = "http:" + probe
            if "://" not in probe:
                # A bare host or address is still a redirect target.
                if not re.match(r"^[\w.\-\[\]:]+$", probe) or "." not in probe:
                    continue
                probe = "http://" + probe
            try:
                sub = urlsplit(probe)
                host = sub.hostname
            except ValueError:
                return name, candidate
            # Scheme first: file:/// and gopher:// have no hostname at all,
            # so a host-led check would skip straight past them.
            if sub.scheme.lower() not in ("http", "https"):
                return name, candidate
            if not host:
                continue
            host = host.strip("[]").rstrip(".").lower()
            try:
                ipaddress.ip_address(host)
            except ValueError:
                pass  # a name, not an address: the allow-list decides
            else:
                if _is_bad_ip(host):
                    return name, candidate
            if host not in ALLOWED_HOSTS:
                return name, candidate
    return None


def check_url(raw_url):
    """Return (allowed, reason, safe_url).

    On success `safe_url` is REBUILT from the components that were validated,
    so the caller fetches exactly what was checked and never the raw input.
    """
    if not isinstance(raw_url, str) or not raw_url:
        return False, "missing or non-string url", None
    if "\x00" in raw_url or len(raw_url) > MAX_PATH_LEN:
        return False, "malformed url", None

    # urlsplit silently strips tab, CR and LF anywhere in the URL, so
    # "https://exam\tple.com/" parses as host example.com and would clear the
    # allow-list. Reject control characters before parsing rather than after.
    if any(ch in raw_url for ch in "\t\r\n\x0b\x0c") or any(ord(ch) < 0x20 for ch in raw_url):
        return False, "control character in url", None

    try:
        parts = urlsplit(raw_url.strip())
    except ValueError:
        return False, "unparseable url", None

    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        return False, f"scheme {parts.scheme or '(none)'} not allowed", None

    netloc = parts.netloc
    if "@" in netloc:
        return False, "userinfo in authority is not allowed", None

    try:
        host = parts.hostname
        port = parts.port
    except ValueError:
        return False, "invalid host or port", None

    if port is not None and port not in (80, 443):
        return False, f"port {port} not allowed", None

    canon, err = _canonical_host(host)
    if err:
        return False, err, None

    # IP literals never match the allow-list, but say so explicitly.
    try:
        ipaddress.ip_address(canon.strip("[]"))
        return False, "raw IP addresses are not allowed", canon
    except ValueError:
        pass

    err = _check_hostname_syntax(canon)
    if err:
        return False, err, canon

    if canon not in ALLOWED_HOSTS:
        return False, f"host {canon} not in allow-list", canon

    # ---- round-trip invariant -------------------------------------------
    # Everything above trusted urlsplit's reading of the authority. The HTTP
    # client re-parses the URL itself, so any construct the two disagree on
    # is an exploit primitive. Require the authority we validated to be
    # *literally* what was sent, modulo case and a default port. Anything
    # needing more folding than that (userinfo, trailing dot, percent
    # escapes, brackets, stray whitespace, a second colon) is ambiguous and
    # gets blocked rather than guessed at.
    default_port = 443 if scheme == "https" else 80
    raw_authority = parts.netloc.lower()
    if raw_authority.endswith(f":{default_port}"):
        raw_authority = raw_authority[: -len(f":{default_port}")]
    if raw_authority != canon:
        return False, "ambiguous authority does not round-trip", canon

    # A path may use '..' freely as long as it never climbs above the root:
    # '/a/../b' is fine, '/../../etc/passwd' is a traversal probe. Same
    # boundary rule as the file guardrail, checked at every decoding depth.
    for variant in _decode_variants(parts.path or ""):
        if _climbs_above_root(variant):
            return False, "url path climbs above document root", canon

    bad_param = _redirect_param_target(parts.query or "")
    if bad_param:
        name, target = bad_param
        return False, f"redirect parameter {name} points at {target}", canon

    # DNS-rebinding defense: every resolved address must be public. Runs
    # AFTER the allow-list match and does not short-circuit it, so a rebound
    # example.com is still rejected here.
    try:
        infos = socket.getaddrinfo(canon, port or default_port, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, OSError):
        infos = []
    for info in infos:
        addr = info[4][0]
        if _is_bad_ip(addr):
            return False, f"host resolves to non-public address {addr}", canon

    # Rebuild from validated components; this, not raw_url, is what we fetch.
    safe_url = urlunsplit((scheme, canon, parts.path, parts.query, ""))

    # The rebuild must itself re-parse to the same host, or our own
    # canonicalization introduced an ambiguity.
    recheck = urlsplit(safe_url)
    if recheck.scheme != scheme or recheck.hostname != canon or recheck.netloc != canon:
        return False, "url does not survive canonical rebuild", canon

    return True, f"host {canon} is allow-listed", safe_url


def _http_get(url):
    """Single request, no automatic redirects. Returns (status, headers, body)."""
    try:
        import httpx

        with httpx.Client(follow_redirects=False, timeout=HTTP_TIMEOUT) as client:
            resp = client.get(url, headers={"User-Agent": "ga5-guardrail/1.0"})
            return resp.status_code, {k.lower(): v for k, v in resp.headers.items()}, resp.text
    except ImportError:
        pass

    import urllib.error
    import urllib.request

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url, headers={"User-Agent": "ga5-guardrail/1.0"})
    try:
        with opener.open(req, timeout=HTTP_TIMEOUT) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, body
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return exc.code, {k.lower(): v for k, v in exc.headers.items()}, body


def do_fetch_url(args):
    url = args.get("url") if isinstance(args, dict) else None
    ok, reason, safe_url = check_url(url)
    if not ok:
        return {"action": "block", "reason": reason, "result": None}

    # Fetch the rebuilt URL, never the raw input, so the string we validated
    # is byte-for-byte the string the HTTP client resolves.
    current = safe_url
    last_error = None
    for _ in range(MAX_REDIRECTS + 1):
        try:
            status, headers, body = _http_get(current)
        except (http.client.InvalidURL, UnicodeError, ValueError) as exc:
            # Not a blip: the URL was malformed enough that the client refused
            # it, which usually means it parsed differently for us than for
            # the client. Treat a disagreement about the target as hostile.
            return {"action": "block",
                    "reason": f"url rejected by http client ({exc.__class__.__name__})",
                    "result": None}
        except Exception as exc:  # network blip - stay permissive, never leak
            last_error = exc.__class__.__name__
            break
        if status in (301, 302, 303, 307, 308):
            location = headers.get("location")
            if not location:
                return {"action": "allow", "reason": reason, "result": body}
            from urllib.parse import urljoin

            nxt = urljoin(current, location)
            # Re-run the FULL policy on every hop, and follow the rebuilt
            # form of the hop rather than the server-supplied string.
            hop_ok, hop_reason, hop_safe = check_url(nxt)
            if not hop_ok:
                return {"action": "block", "reason": f"redirect to disallowed target: {hop_reason}",
                        "result": None}
            current = hop_safe
            continue
        return {"action": "allow", "reason": reason, "result": body}
    else:
        return {"action": "block", "reason": "too many redirects", "result": None}

    return {"action": "allow", "reason": f"{reason} (fetch unavailable: {last_error})", "result": ""}


# --------------------------------------------------------------------------
# Endpoint
# --------------------------------------------------------------------------

def evaluate(payload):
    if not isinstance(payload, dict):
        return {"action": "block", "reason": "malformed request body", "result": None}
    tool = payload.get("tool")
    args = payload.get("arguments")
    if not isinstance(args, dict):
        args = {k: v for k, v in payload.items() if k in ("path", "url")}

    if tool == "read_file":
        out = do_read_file(args)
    elif tool == "fetch_url":
        out = do_fetch_url(args)
    else:
        out = {"action": "block", "reason": f"unknown tool {tool!r}", "result": None}

    # Belt and braces: never let the canary leave the process, whatever
    # path got us here.
    if CANARY in repr(out):
        return {"action": "block", "reason": "response withheld: sandbox violation", "result": None}
    if out.get("action") == "block":
        out["result"] = None
    return out


@router.post("/q8/check")
async def q8_check(request: Request):
    try:
        payload = await request.json()
    except Exception:
        payload = None
    # evaluate() does blocking DNS and HTTP work. On Render's 0.1-CPU free
    # instance, running that on the event loop serialises the grader's
    # concurrent battery behind one slow fetch and the later probes error
    # out, so hand it to the threadpool.
    return await run_in_threadpool(evaluate, payload)


@router.post("/check")
async def q8_check_alias(request: Request):
    try:
        payload = await request.json()
    except Exception:
        payload = None
    # evaluate() does blocking DNS and HTTP work. On Render's 0.1-CPU free
    # instance, running that on the event loop serialises the grader's
    # concurrent battery behind one slow fetch and the later probes error
    # out, so hand it to the threadpool.
    return await run_in_threadpool(evaluate, payload)
