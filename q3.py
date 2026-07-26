import base64
import os
import re
from urllib.parse import urlparse

from fastapi import APIRouter, Request

router = APIRouter()

WORKSPACE = "/home/agent/workspace"
HOME = "/home/agent"
SECRET = "/home/agent/service-account.json"
WRITE_ROOT = "/srv/reports"
ALLOWED_HOSTS = {
    "api.github.com",
    "registry.npmjs.org",
}


def normalize_path(path: str):
    path = path.replace("$HOME", HOME)
    path = path.replace("~", HOME)

    if not os.path.isabs(path):
        path = os.path.join(WORKSPACE, path)

    return os.path.normpath(path)


def resolves_inside(path: str, root: str):
    path = normalize_path(path)
    root = os.path.normpath(root)
    return path == root or path.startswith(root + os.sep)


def contains_secret(command: str):
    c = command.replace("$HOME", HOME).replace("~", HOME)

    # relative traversal
    c = c.replace("../", "")

    if SECRET in c:
        return True

    # base64 wrapped command
    b64 = re.findall(r"[A-Za-z0-9+/=]{20,}", command)

    for token in b64:
        try:
            decoded = base64.b64decode(token).decode(errors="ignore")
            if SECRET in decoded:
                return True
        except Exception:
            pass

    return False


@router.post("/")
async def guard(req: Request):
    body = await req.json()

    tool = body["tool"]

    if tool == "bash":
        if contains_secret(body["command"]):
            return {
                "decision": "block",
                "reason": "Attempt to read protected secret."
            }

        return {
            "decision": "allow",
            "reason": "Command allowed."
        }

    if tool == "write_file":
        if resolves_inside(body["path"], WRITE_ROOT):
            return {
                "decision": "allow",
                "reason": "Write inside permitted directory."
            }

        return {
            "decision": "block",
            "reason": "Write outside permitted directory."
        }

    if tool == "http_request":
        host = urlparse(body["url"]).hostname or ""

        if host in ALLOWED_HOSTS:
            return {
                "decision": "allow",
                "reason": "Host permitted."
            }

        return {
            "decision": "block",
            "reason": "Host not permitted."
        }

    return {
        "decision": "allow",
        "reason": "Unknown tool."
    }
