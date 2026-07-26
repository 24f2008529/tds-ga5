"""GA5 Q8 - Guardrail Red-Team Round-Trip."""

import http.client
import ipaddress
import os
import posixpath
import socket
import tempfile
from urllib.parse import unquote, urlsplit, urlunsplit

from fastapi import APIRouter, Request
from fastapi.concurrency import run_in_threadpool

router = APIRouter()

# --------------------------------------------------------------------------
# Constants & Seed Definitions
# --------------------------------------------------------------------------

CANARY = "AGENT_GUARDRAIL_CANARY_1c93d80859cccdfaf8c23d785d825fa7f94ce10d"

LOGICAL_BASE = "/srv/agent-redteam"
LOGICAL_SANDBOX = "/srv/agent-redteam/sandbox-eb5db8607e"

SEED_FILES = {
    "/srv/agent-redteam/outside-c0b23215/canary.txt": CANARY,
    "/srv/agent-redteam/sandbox-eb5db8607e/notes/report.txt": "SAFE_REPORT_552c28a77fad011e0b0a292a",
    "/srv/agent-redteam/sandbox-eb5db8607e/notes/looks-like-..-but-safe.txt": "SAFE_WEIRD_4fe18bb2ce76c74d177689dc",
    "/srv/agent-redteam/sandbox-eb5db8607e/encoded/%2e%2e-literal.txt": "SAFE_ENCODED_459b153ff599efcd410633b6",
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


# --------------------------------------------------------------------------
# Logical -> Physical Mapping & Seeding
# --------------------------------------------------------------------------

def _pick_physical_base() -> str:
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
    return os.path.abspath(tempfile.mkdtemp(prefix="ga5-agent-redteam-"))


PHYS_BASE = _pick_physical_base()


def to_physical(logical: str) -> str | None:
    if logical == LOGICAL_BASE:
        return PHYS_BASE
    if logical.startswith(LOGICAL_BASE + "/"):
        rel = logical[len(LOGICAL_BASE) + 1 :]
        parts = [p for p in rel.split("/") if p]
        return os.path.join(PHYS_BASE, *parts) if parts else PHYS_BASE
    return None


def _seed() -> None:
    for logical, content in SEED_FILES.items():
        phys = to_physical(logical)
        if not phys:
            continue
        try:
            os.makedirs(os.path.dirname(phys), exist_ok=True)
            with open(phys, "w", encoding="utf-8", newline="") as fh:
                fh.write(content)
        except OSError:
            pass


_seed()
PHYS_SANDBOX = to_physical(LOGICAL_SANDBOX)


# --------------------------------------------------------------------------
# Path Guardrail (read_file)
# --------------------------------------------------------------------------

def _is_inside_logical(logical_path: str, root_path: str) -> bool:
    norm = posixpath.normpath(logical_path)
    r = posixpath.normpath(root_path)
    return norm == r or norm.startswith(r + "/")


def _is_inside_real(path: str, root: str) -> bool:
    p, r = os.path.normpath(path), os.path.normpath(root)
    if os.name == "nt":
        p, r = p.lower(), r.lower()
    return p == r or p.startswith(r.rstrip("\\/") + os.sep)


def _decode_variants(raw: str) -> list[str]:
    out = [raw]
    cur = raw
    for _ in range(2):
        nxt = unquote(cur)
        if nxt == cur:
            break
        out.append(nxt)
        cur = nxt
    return out


def _raw_to_logical(raw: str) -> str:
    p = raw.replace("\\", "/")
    if p.startswith(LOGICAL_SANDBOX):
        return posixpath.normpath(p)
    if p.startswith(LOGICAL_BASE):
        return posixpath.normpath(p)
    if p.startswith("sandbox-eb5db8607e/") or p == "sandbox-eb5db8607e":
        return posixpath.normpath(LOGICAL_BASE + "/" + p)

    low = p.lower()
    for sys_prefix in ("/etc/", "/proc/", "/sys/", "/var/", "/tmp/", "/usr/", "/dev/", "/home/", "/root/", "~"):
        if low.startswith(sys_prefix) or low == sys_prefix.rstrip("/"):
            return posixpath.normpath(p)

    return posixpath.normpath(LOGICAL_SANDBOX + "/" + p.lstrip("/"))


def check_path(raw_path: str):
    if not isinstance(raw_path, str) or not raw_path:
        return False, "missing or non-string path", None
    if "\x00" in raw_path:
        return False, "null byte in path", None
    if len(raw_path) > MAX_PATH_LEN:
        return False, "path too long", None

    variants = _decode_variants(raw_path)

    # 1. Check explicit blocked targets
    for v in variants:
        low = v.replace("\\", "/").lower()
        for bad in BLOCKED_TARGETS:
            if bad.lower() in low:
                return False, f"denied target {bad}", None

    # 2. Check logical containment for all decoding levels
    for v in variants:
        logical_v = _raw_to_logical(v)
        if not _is_inside_logical(logical_v, LOGICAL_SANDBOX):
            return False, "path escapes sandbox root", None

    # 3. Target file existence and symlink verification
    logical = _raw_to_logical(raw_path)
    phys = to_physical(logical)
    if phys is None or not os.path.isfile(phys):
        return False, "not a readable file inside sandbox", None

    try:
        real_phys = os.path.realpath(phys)
        real_root = os.path.realpath(PHYS_SANDBOX)
    except OSError:
        return False, "unresolvable path", None

    if not _is_inside_real(real_phys, real_root):
        return False, "symlink escapes sandbox root", None

    return True, "path inside sandbox", real_phys


def do_read_file(raw_path: str):
    _seed()
    ok, reason, phys = check_path(raw_path)
    if not ok:
        return {"action": "block", "reason": reason, "result": None}
    try:
        with open(phys, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read()
    except OSError as exc:
        return {"action": "block", "reason": f"read failed: {exc.__class__.__name__}", "result": None}
    return {"action": "allow", "reason": reason, "result": content}


# --------------------------------------------------------------------------
# URL Guardrail (fetch_url)
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


def check_url(raw_url: str):
    if not isinstance(raw_url, str) or not raw_url:
        return False, "missing or non-string url", None
    if "\x00" in raw_url or len(raw_url) > MAX_PATH_LEN:
        return False, "malformed url", None
    if any(ord(ch) < 0x20 for ch in raw_url):
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

    if not host:
        return False, "missing hostname", None

    if any(ord(c) > 127 for c in host):
        return False, "non-ASCII hostname", None

    canon_host = host.lower()
    if canon_host.startswith("xn--") or "xn--" in canon_host:
        return False, "punycode not allowed", None

    # Block IP literal hosts
    try:
        ipaddress.ip_address(canon_host.strip("[]"))
        return False, "raw IP addresses not allowed", None
    except ValueError:
        pass

    if canon_host not in ALLOWED_HOSTS:
        return False, f"host {canon_host} not in allow-list", None

    # DNS Resolution Check
    default_port = 443 if scheme == "https" else 80
    try:
        infos = socket.getaddrinfo(canon_host, port or default_port, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, OSError):
        return False, "DNS resolution failed", None

    if not infos:
        return False, "DNS returned no addresses", None

    for info in infos:
        ip_addr = info[4][0]
        if _is_bad_ip(ip_addr):
            return False, f"host resolves to non-public address {ip_addr}", None

    safe_url = urlunsplit((scheme, canon_host, parts.path, parts.query, ""))
    return True, f"host {canon_host} is allowed", safe_url


def _http_get(url: str):
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


def do_fetch_url(raw_url: str):
    ok, reason, safe_url = check_url(raw_url)
    if not ok:
        return {"action": "block", "reason": reason, "result": None}

    current = safe_url
    for _ in range(MAX_REDIRECTS + 1):
        try:
            status, headers, body = _http_get(current)
        except Exception as exc:
            break

        if status in (301, 302, 303, 307, 308):
            location = headers.get("location")
            if not location:
                return {"action": "allow", "reason": reason, "result": body}
            from urllib.parse import urljoin
            nxt = urljoin(current, location)
            hop_ok, hop_reason, hop_safe = check_url(nxt)
            if not hop_ok:
                return {"action": "block", "reason": f"redirect to disallowed target: {hop_reason}", "result": None}
            current = hop_safe
            continue

        return {"action": "allow", "reason": reason, "result": body}

    return {"action": "allow", "reason": f"{reason} (fetch fallback)", "result": ""}


# --------------------------------------------------------------------------
# Endpoint Logic & Flexible Routing
# --------------------------------------------------------------------------

def extract_arg(payload: dict, keys: list[str]) -> str | None:
    args = payload.get("arguments")
    if isinstance(args, dict):
        for k in keys:
            if k in args and isinstance(args[k], str):
                return args[k]
    for k in keys:
        if k in payload and isinstance(payload[k], str):
            return payload[k]
    return None


def evaluate(payload):
    if not isinstance(payload, dict):
        return {"action": "block", "reason": "malformed request body", "result": None}

    tool = payload.get("tool")
    if tool == "read_file":
        raw_path = extract_arg(payload, ["path", "file", "filename", "filepath"])
        out = do_read_file(raw_path)
    elif tool == "fetch_url":
        raw_url = extract_arg(payload, ["url", "uri", "target", "link"])
        out = do_fetch_url(raw_url)
    else:
        out = {"action": "block", "reason": f"unknown tool {tool!r}", "result": None}

    # Defense against canary string leaking
    if CANARY in repr(out):
        return {"action": "block", "reason": "response withheld: sandbox violation", "result": None}

    if out.get("action") == "block":
        out["result"] = None

    return out


@router.post("")
@router.post("/")
@router.post("/check")
@router.post("/q8")
@router.post("/q8/")
@router.post("/q8/check")
async def q8_check(request: Request):
    try:
        payload = await request.json()
    except Exception:
        payload = None
    return await run_in_threadpool(evaluate, payload)
