import calendar
from fastapi import APIRouter, Request

router = APIRouter()

@router.post("/prorate")
async def prorate(req: Request):
    b = await req.json()

    old = b["old_price"]
    new = b["new_price"]
    year = b["year"]
    month = b["month"]
    day = b["upgrade_day"]

    dim = calendar.monthrange(year, month)[1]
    remaining = dim - day + 1

    charge = round((new - old) * (remaining / dim), 2)

    return {"charge": charge}
