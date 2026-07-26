import re

from fastapi import APIRouter, Request

router = APIRouter()


SECRET_PATTERNS = [
    r"AKIA[0-9A-Z]{16}",                    # AWS
    r"AIza[0-9A-Za-z\-_]{35}",             # Google
    r"gh[pousr]_[A-Za-z0-9]{36,}",         # GitHub
    r"sk-[A-Za-z0-9]{20,}",                # OpenAI-like
    r"xox[baprs]-[A-Za-z0-9\-]{10,}",      # Slack
    r"https://hooks\.slack\.com/services/[^\s]+",
    r"-----BEGIN (?:RSA|EC|OPENSSH|PRIVATE) KEY-----",
]

UNSCOPED_PERMISSION = [
    r"read[- ]?write.*entire filesystem",
    r"read[- ]?write.*whole filesystem",
    r"read[- ]?write.*/\b",
    r"whole home directory",
    r"entire home directory",
    r"filesystem.*entire",
    r"unrestricted egress",
    r"unlimited egress",
    r"egress.*any\s+(?:external\s+)?domain",
    r"egress.*all\s+(?:external\s+)?domains",
    r"access.*entire filesystem",
    r"access.*whole filesystem",
]

PROMPT_INJECTION = [
    r"ignore.{0,80}(?:user).{0,80}(?:stop|cancel|pause|halt)",
    r"(?:stop|cancel|pause|halt).{0,80}ignore",
    r"override.{0,80}(?:user)",
    r"disregard.{0,80}(?:user)",
    r"exfiltrat",
    r"silently.*send",
    r"silently.*upload",
]


@router.post("/")
async def scan(req: Request):
    body = await req.json()
    skill = body.get("skill", "")

    text = skill.lower()

    categories = []

    # hardcoded_secret
    if any(re.search(p, skill) for p in SECRET_PATTERNS):
        categories.append("hardcoded_secret")
    elif re.search(
        r"(api[_ -]?key|token|secret|password)\s*[:=]\s*['\"]?[A-Za-z0-9_\-\/+=]{16,}",
        skill,
        re.I,
    ):
        categories.append("hardcoded_secret")

    # excessive_permissions
    if any(re.search(p, text) for p in UNSCOPED_PERMISSION):
        categories.append("excessive_permissions")

    # prompt_injection
    if any(re.search(p, text) for p in PROMPT_INJECTION):
        categories.append("prompt_injection")

    return {"categories": categories}
