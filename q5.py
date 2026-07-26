import json
import re

from fastapi import APIRouter, Request

router = APIRouter()


def normalize(value):
    if isinstance(value, dict):
        return {
            k: normalize(v)
            for k, v in sorted(value.items())
            if k != "request_id"
        }

    if isinstance(value, list):
        return [normalize(v) for v in value]

    if isinstance(value, str):
        return re.sub(r"\s+", " ", value).strip()

    return value


def key(step):
    return (
        step["tool"],
        json.dumps(normalize(step.get("args", {})), sort_keys=True),
    )


def three_repeat(steps):
    if len(steps) < 3:
        return False

    last = key(steps[-1])

    count = 1

    for s in reversed(steps[:-1]):
        if key(s) == last:
            count += 1
        else:
            break

    return count >= 3


def two_cycle(steps):
    if len(steps) < 6:
        return False

    tail = steps[-6:]

    a = key(tail[0])
    b = key(tail[1])

    if a == b:
        return False

    pattern = [a, b, a, b, a, b]

    return [key(x) for x in tail] == pattern


@router.post("/")
async def check(req: Request):
    body = await req.json()

    budget = body["budget_tokens"]
    steps = body.get("steps", [])

    used = sum(step["tokens_used"] for step in steps)

    if used >= budget:
        return {
            "decision": "halt",
            "reason": f"Cumulative tokens_used ({used}) has reached the budget ({budget}).",
        }

    if three_repeat(steps):
        return {
            "decision": "halt",
            "reason": "Repeated identical tool call detected.",
        }

    if two_cycle(steps):
        return {
            "decision": "halt",
            "reason": "Detected repeating two-step cycle.",
        }

    return {
        "decision": "continue",
        "reason": "Under budget and making progress.",
    }
