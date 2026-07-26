from fastapi import FastAPI
from hashlib import sha256

from mcp.server.fastmcp import FastMCP, Context

from q2 import router as q2_router
from q3 import router as q3_router
from q4 import router as q4_router
from q5 import router as q5_router
from q8 import router as q8_router

EMAIL = "24f2008529@ds.study.iitm.ac.in".strip().lower()

app = FastAPI()

app.include_router(q2_router, prefix="/q2")
app.include_router(q3_router, prefix="/q3")
app.include_router(q4_router, prefix="/q4")
app.include_router(q5_router, prefix="/q5")
app.include_router(q8_router, prefix="/q8")

mcp = FastMCP("exam")


@mcp.tool()
async def solve_challenge(ctx: Context) -> str:
    challenge = ctx.request.headers["X-Exam-Challenge"]
    return sha256(f"{challenge}:{EMAIL}".encode()).hexdigest()[:16]


# Mount the MCP app
app.mount("/", mcp.streamable_http_app())
