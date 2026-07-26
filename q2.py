from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()


class ProrationRequest(BaseModel):
    old_price: float
    new_price: float
    days_remaining: int
    days_in_actual_month: int
    spec: str


@router.post("/")
def prorate(data: ProrationRequest):
    diff = data.new_price - data.old_price

    if data.spec == "v1":
        divisor = 30
    elif data.spec == "v2":
        divisor = data.days_in_actual_month
    else:
        return {"error": "Invalid spec"}

    charge = round(diff * data.days_remaining / divisor, 2)

    return {"charge": charge}
