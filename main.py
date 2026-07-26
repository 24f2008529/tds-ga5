from contextlib import asynccontextmanager
from hashlib import sha256
from fastapi import FastAPI
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

# Normalized exam email
EMAIL = "24f2008529@ds.study.iitm.ac.in".strip().lower()

# Global store to bridge header data across FastMCP background task boundaries
LATEST_HEADERS: dict[str, str] = {}


# Pure ASGI Middleware to inspect and store incoming headers
class HeaderASGIMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] in ("http", "websocket"):
            headers = {
                k.decode("latin1").lower(): v.decode("latin1")
                for k, v in scope.get("headers", [])
            }
            # Capture x-exam-challenge whenever present in incoming requests
            if "x-exam-challenge" in headers:
                LATEST_HEADERS["x-exam-challenge"] = headers["x-exam-challenge"]

        await self.app(scope, receive, send)


# Initialize FastMCP with DNS rebinding protection DISABLED
mcp = FastMCP(
    "exam",
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=False
    ),
)


@mcp.tool()
async def solve_challenge(challenge: str = "") -> str:
    """Solves the challenge using SHA-256 and the normalized email.

    Supports obtaining the challenge either via tool arguments or the X-Exam-Challenge header.
    """
    # 1. Fall back to header store if challenge argument is empty
    ch = challenge.strip() or LATEST_HEADERS.get("x-exam-challenge", "").strip()

    # 2. Compute SHA-256("${challenge}:${normalizedEmail}")
    payload = f"{ch}:{EMAIL}".encode("utf-8")
    return sha256(payload).hexdigest()[:16]


# Build streamable HTTP application
mcp_app = mcp.streamable_http_app()


# Explicitly invoke FastMCP's internal task group via FastAPI's lifespan
@asynccontextmanager
async def lifespan(app: FastAPI):
    async with mcp_app.router.lifespan_context(mcp_app):
        yield


# Initialize main FastAPI instance
app = FastAPI(lifespan=lifespan)

# Add middleware for header interception
app.add_middleware(HeaderASGIMiddleware)

# Include question routers
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

# Mount MCP app at /mcp to match your submission URL
app.mount("/mcp", mcp_app)
# Also mount at root for backward compatibility
app.mount("/", mcp_app)
