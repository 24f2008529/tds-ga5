import base64
import fnmatch
import os
import re
import urllib.parse
from urllib.parse import urlparse

from fastapi import APIRouter, Request

router = APIRouter()

WORKSPACE = "/home/agent/workspace"
HOME = "/home/agent"
SECRET_FILE = "/home/agent/service-account.json"
WRITE_ROOT = "/srv/reports"
ALLOWED_HOSTS = {
    "api.github.com",
    "registry.npmjs.org",
}


def normalize_write_path(path: str) -> str:
    """Normalizes write_file paths, unquoting URL encoding and expanding variables."""
    if not isinstance(path, str):
        return ""

    # Unquote URL encoding up to 3 times to prevent nested encoding tricks (%252e)
    for _ in range(3):
        unquoted = urllib.parse.unquote(path)
        if unquoted == path:
            break
        path = unquoted

    # Handle null byte injection
    path = path.split("\0")[0]

    # Standardize path separators
    path = path.replace("\\", "/")

    # Expand environment variables and tildes
    path = path.replace("${HOME}", HOME).replace("$HOME", HOME)
    path = path.replace("${WORKSPACE}", WORKSPACE).replace("$WORKSPACE", WORKSPACE)
    path = path.replace("${PWD}", WORKSPACE).replace("$PWD", WORKSPACE)

    if path == "~" or path.startswith("~/"):
        path = HOME + path[1:]
    elif path.startswith("~agent"):
        path = HOME + path[6:]

    # Make relative paths absolute against WORKSPACE
    if not os.path.isabs(path):
        path = os.path.join(WORKSPACE, path)

    return os.path.normpath(path)


def is_write_allowed(path: str) -> bool:
    """Checks if path is strictly inside /srv/reports/."""
    norm = normalize_write_path(path)
    # Must strictly start with /srv/reports/ (subdirectories or files within)
    return norm.startswith("/srv/reports/")


def decode_and_expand_variants(cmd: str) -> list[str]:
    """Generates all decoded, unquoted, and variable-expanded string variants of a command."""
    variants = [cmd]

    # URL decoding
    unquoted = urllib.parse.unquote(cmd)
    if unquoted not in variants:
        variants.append(unquoted)

    # Hex decoding (\x2f...)
    try:
        hex_decoded = re.sub(
            r"\\x([0-9a-fA-F]{2})",
            lambda m: bytes.fromhex(m.group(1)).decode(errors="ignore"),
            cmd,
        )
        if hex_decoded not in variants:
            variants.append(hex_decoded)
    except Exception:
        pass

    # Octal decoding (\057...)
    try:
        oct_decoded = re.sub(
            r"\\([0-7]{1,3})", lambda m: chr(int(m.group(1), 8)), cmd
        )
        if oct_decoded not in variants:
            variants.append(oct_decoded)
    except Exception:
        pass

    # Extract and decode potential Base64 tokens
    b64_tokens = re.findall(r"[A-Za-z0-9+/=]{8,}", cmd)
    for token in b64_tokens:
        try:
            decoded = base64.b64decode(token).decode(errors="ignore")
            if decoded and decoded not in variants:
                variants.append(decoded)
        except Exception:
            pass

    # Perform shell variable & tilde expansions on all variants
    expanded_variants = []
    for v in variants:
        expanded_variants.append(v)
        v_sub = (
            v.replace("${HOME}", HOME)
            .replace("$HOME", HOME)
            .replace("~agent", HOME)
            .replace("~/", HOME + "/")
            .replace("${PWD}", WORKSPACE)
            .replace("$PWD", WORKSPACE)
            .replace("${WORKSPACE}", WORKSPACE)
            .replace("$WORKSPACE", WORKSPACE)
            .replace("${USER}", "agent")
            .replace("$USER", "agent")
        )
        if v_sub not in expanded_variants:
            expanded_variants.append(v_sub)

        # Strip quote marks and backslashes to catch split string tricks ('service'-'account')
        cleaned = re.sub(r'["\'\\]', "", v_sub)
        if cleaned not in expanded_variants:
            expanded_variants.append(cleaned)

    return expanded_variants


def is_bash_command_blocked(command: str) -> bool:
    """Deterministically checks if a bash command attempts to access protected secrets."""
    if not isinstance(command, str):
        return True

    variants = decode_and_expand_variants(command)

    # 1. Direct keyword check across variants
    for v in variants:
        v_lower = v.lower()
        if (
            "service-account.json" in v_lower
            or "service-account" in v_lower
            or "service_account" in v_lower
            or "/etc/shadow" in v_lower
            or "/etc/sudoers" in v_lower
        ):
            return True

    # 2. Tokenize and normalize paths & globs
    for v in variants:
        tokens = re.split(r'[\s;\|&><`"\']+', v)
        for token in tokens:
            token = token.strip()
            if not token:
                continue

            token_unquoted = urllib.parse.unquote(token)

            # Check resolved absolute and relative path targets
            if os.path.isabs(token_unquoted):
                norm = os.path.normpath(token_unquoted)
            elif token_unquoted.startswith("..") or token_unquoted.startswith("."):
                norm = os.path.normpath(os.path.join(WORKSPACE, token_unquoted))
            else:
                norm = None

            if norm and (norm == SECRET_FILE or norm == "/etc/shadow"):
                return True

            # Glob matching check (e.g. /home/agent/*.json or ../service*)
            glob_candidate = token_unquoted
            if not os.path.isabs(glob_candidate) and ("*" in glob_candidate or "?" in glob_candidate):
                glob_candidate = os.path.normpath(os.path.join(WORKSPACE, glob_candidate))

            if "*" in glob_candidate or "?" in glob_candidate:
                if fnmatch.fnmatch(SECRET_FILE, glob_candidate) or fnmatch.fnmatch("/etc/shadow", glob_candidate):
                    return True

    return False


def is_http_allowed(url: str) -> bool:
    if not isinstance(url, str):
        return False

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower().strip()
        return host in ALLOWED_HOSTS
    except Exception:
        return False


@router.post("/")
async def guard(req: Request):
    try:
        body = await req.json()
    except Exception:
        return {"decision": "block", "reason": "Invalid JSON body."}

    tool = body.get("tool")

    if tool == "bash":
        cmd = body.get("command", "")
        if is_bash_command_blocked(cmd):
            return {
                "decision": "block",
                "reason": "Command contains forbidden file path or secret access.",
            }
        return {
            "decision": "allow",
            "reason": "Command allowed.",
        }

    if tool == "write_file":
        path = body.get("path", "")
        if is_write_allowed(path):
            return {
                "decision": "allow",
                "reason": "Write inside permitted directory.",
            }
        return {
            "decision": "block",
            "reason": "Write outside permitted directory.",
        }

    if tool == "http_request":
        url = body.get("url", "")
        if is_http_allowed(url):
            return {
                "decision": "allow",
                "reason": "Host permitted.",
            }
        return {
            "decision": "block",
            "reason": "Host not permitted.",
        }

    return {
        "decision": "block",
        "reason": "Unknown tool requested.",
    }
