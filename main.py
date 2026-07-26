from fastapi import FastAPI
from q1 import router as q1_router
from q2 import router as q2_router

app = FastAPI()

app.include_router(q2_router, prefix="/q2")
