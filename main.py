from contextvars import ContextVar
from hashlib import sha256
from fastapi import FastAPI
from mcp.server.fastmcp import FastMCP

# Normalized exam email
EMAIL = "24f2008529@ds.study.iitm.ac.in".strip().lower()

# ContextVar to store request headers for the current async execution context
current_request_headers: ContextVar[dict] = ContextVar("current_request_headers", default={})


# Pure ASGI Middleware to safely intercept headers on all incoming requests
class HeaderASGIMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] in ("http", "websocket"):
            # Lowercase all header keys for consistent lookup
            headers = {
                k.decode("latin1").lower(): v.decode("latin1")
                for k, v in scope.get("headers", [])
            }
            token = current_request_headers.set(headers)
            try:
                await self.app(scope, receive, send)
            finally:
                current_request_headers.reset(token)
        else:
            await self.app(scope, receive, send)


app = FastAPI()

# Include routers from other exam questions if applicable
from q2 import router as q2_router
from q3 import router as q3_router
from q4 import router as q4_router
from q5 import router as q5_router
from q8 import router as q8_router

app.include_router(q2_router, prefix="/q2")
app.include_router(q3_router, prefix="/q3")
app.include_router(q4_router, prefix="/q4")
app.include_router(q5_router, prefix="/q5")
app.include_router(q8_router, prefix="/q8")

# Add header extraction middleware
app.add_middleware(HeaderASGIMiddleware)

# Expose EXACTLY ONE tool named solve_challenge
mcp = FastMCP("exam")


@mcp.tool()
async def solve_challenge() -> str:
    """Solves the challenge header using SHA-256 and the normalized email."""
    headers = current_request_headers.get()

    # Read fresh challenge from X-Exam-Challenge header
    challenge = headers.get("x-exam-challenge", "")

    # Compute SHA-256("${challenge}:${normalizedEmail}")
    payload = f"{challenge}:{EMAIL}".encode("utf-8")
    return sha256(payload).hexdigest()[:16]


# Mount the MCP application (supports streamable HTTP or SSE app)
if hasattr(mcp, "streamable_http_app"):
    app.mount("/", mcp.streamable_http_app())
else:
    app.mount("/", mcp.sse_app())
