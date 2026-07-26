import os
from urllib.parse import urlparse

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()


class Config(BaseModel):
    secret_files: list[str]
    write_dir: str
    allowed_domains: list[str]


class ToolCall(BaseModel):
    tool: str
    arguments: dict


class CheckRequest(BaseModel):
    call: ToolCall
    cfg: Config


def resolves_inside(path: str, root: str) -> bool:
    if os.path.isabs(path):
        full = os.path.normpath(path)
    else:
        full = os.path.normpath(os.path.join(root, path))

    root = os.path.normpath(root)

    return full == root or full.startswith(root + os.sep)


def extract_host(url: str) -> str:
    return urlparse(url).hostname or ""


@router.post("/")
def check(req: CheckRequest):
    tool = req.call.tool
    args = req.call.arguments
    cfg = req.cfg

    if tool == "read_file":
        p = os.path.normpath(args["path"])

        if any(p.endswith(s) or s in p for s in cfg.secret_files):
            return {"decision": "block"}

        return {"decision": "allow"}

    if tool == "write_file":
        if resolves_inside(args["path"], cfg.write_dir):
            return {"decision": "allow"}

        return {"decision": "block"}

    if tool in ("network", "fetch", "http"):
        host = extract_host(args["url"])

        if host in cfg.allowed_domains:
            return {"decision": "allow"}

        return {"decision": "block"}

    return {"decision": "allow"}
