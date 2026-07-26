from fastapi import FastAPI

from q2 import router as q2_router
from q3 import router as q3_router
from q4 import router as q4_router

app = FastAPI()

app.include_router(q2_router, prefix="/q2")
app.include_router(q3_router, prefix="/q3")
app.include_router(q4_router, prefix="/q4")
