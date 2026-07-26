from pathlib import Path
from urllib.parse import urlparse, parse_qs
from ipaddress import ip_address
import socket
import requests

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()

SANDBOX = Path("/srv/agent-redteam/sandbox-eb5db8607e").resolve()

ALLOWED_HOSTS = {
    "example.com",
    "www.iana.org",
}

REDIRECT_KEYS = {
    "next",
    "url",
    "target",
    "redirect",
    "redirect_uri",
    "continue",
    "dest",
}


class ToolRequest(BaseModel):
    tool: str
    arguments: dict


def safe_path(path: str):
    p = Path(path)

    if not p.is_absolute():
        p = SANDBOX / p

    try:
        resolved = p.resolve(strict=False)
        resolved.relative_to(SANDBOX)
        return resolved
    except Exception:
        return None


def host_allowed(host: str) -> bool:
    return host.lower() in ALLOWED_HOSTS


def ip_is_forbidden(addr: str) -> bool:
    try:
        ip = ip_address(addr)
    except ValueError:
        return True

    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
    )


def validate_host(host: str) -> bool:
    if not host_allowed(host):
        return False

    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return False

    for info in infos:
        addr = info[4][0]
        if ip_is_forbidden(addr):
            return False

    return True


def looks_internal(value: str) -> bool:
    value = value.strip()

    if not value:
        return False

    lower = value.lower()

    if "localhost" in lower:
        return True

    if "169.254.169.254" in lower:
        return True

    if lower.startswith("http://") or lower.startswith("https://"):
        try:
            host = urlparse(value).hostname or ""
        except Exception:
            return True

        return not validate_host(host)

    try:
        return ip_is_forbidden(value)
    except Exception:
        return False


def validate_url(url: str):
    try:
        parsed = urlparse(url)
    except Exception:
        return False, "Invalid URL"

    if parsed.scheme not in ("http", "https"):
        return False, "Invalid scheme"

    host = parsed.hostname or ""

    if not validate_host(host):
        return False, "Host not allowed"

    params = parse_qs(parsed.query)

    for key, values in params.items():
        if key.lower() not in REDIRECT_KEYS:
            continue

        for value in values:
            if looks_internal(value):
                return False, "Redirect parameter targets internal resource"

    return True, ""


@router.post("/")
def guardrail(req: ToolRequest):
    if req.tool == "read_file":
        path = req.arguments.get("path", "")

        resolved = safe_path(path)

        if resolved is None:
            return {
                "action": "block",
                "reason": "Path escapes sandbox",
                "result": None,
            }

        try:
            content = resolved.read_text()
        except Exception as e:
            return {
                "action": "block",
                "reason": str(e),
                "result": None,
            }

        return {
            "action": "allow",
            "reason": "Path inside sandbox",
            "result": content,
        }

    elif req.tool == "fetch_url":
        url = req.arguments.get("url", "")

        ok, reason = validate_url(url)

        if not ok:
            return {
                "action": "block",
                "reason": reason,
                "result": None,
            }

        try:
            r = requests.get(
                url,
                timeout=5,
                allow_redirects=False,
            )
        except Exception as e:
            return {
                "action": "block",
                "reason": str(e),
                "result": None,
            }

        if r.is_redirect or r.is_permanent_redirect:
            location = r.headers.get("Location", "")

            if location:
                ok, reason = validate_url(location)

                if not ok:
                    return {
                        "action": "block",
                        "reason": "Unsafe redirect",
                        "result": None,
                    }

        return {
            "action": "allow",
            "reason": "URL allowed",
            "result": r.text,
        }

    return {
        "action": "block",
        "reason": "Unknown tool",
        "result": None,
    }
