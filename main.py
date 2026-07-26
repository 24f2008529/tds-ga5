from fastapi import FastAPI

from q2 import router as q2_router
from q3 import router as q3_router

app = FastAPI()

app.include_router(q2_router, prefix="/q2")
app.include_router(q3_router, prefix="/q3")
