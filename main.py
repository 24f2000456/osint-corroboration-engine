from datetime import datetime
from fastapi import FastAPI, Request

app = FastAPI()

VALID_TYPES = {"dns", "ct_log", "registry", "archive", "scan"}


def invalid():
    return {
        "verdict": "invalid",
        "confidence": "low",
        "corroboratingSources": []
    }


def parse_time(value):
    if not isinstance(value, str):
        return None

    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


@app.get("/")
def root():
    return {"status": "ok"}


@app.post("/corroborate")
async def corroborate(request: Request):

    # Read the raw JSON body ourselves.
    try:
        body = await request.json()
    except Exception:
        return invalid()

    # Rule 1
    if not isinstance(body, dict):
        return invalid()

    claim = body.get("claim")

    if not isinstance(claim, dict):
        return invalid()

    claim_value = claim.get("value")

    if not isinstance(claim_value, str):
        return invalid()

    as_of = parse_time(body.get("asOf"))

    if as_of is None:
        return invalid()

    staleness_days = body.get("stalenessDays")

    if isinstance(staleness_days, bool):
        return invalid()

    if not isinstance(staleness_days, (int, float)):
        return invalid()

    sources = body.get("sources")

    if not isinstance(sources, list):
        return invalid()

    # Keep only valid and fresh sources
    fresh = []

    for source in sources:

        if not isinstance(source, dict):
            continue

        if not isinstance(source.get("id"), str):
            continue

        if not isinstance(source.get("origin"), str):
            continue

        if not isinstance(source.get("value"), str):
            continue

        if not isinstance(source.get("observedAt"), str):
            continue

        if source.get("type") not in VALID_TYPES:
            continue

        observed_at = parse_time(source["observedAt"])

        if observed_at is None:
            continue

        age_days = (
            as_of - observed_at
        ).total_seconds() / 86400

        if age_days <= staleness_days:
            fresh.append(source)

    # Rule 2: fresh authoritative contradiction
    contradictions = [
        source["id"]
        for source in fresh
        if source.get("authoritative") is True
        and source["value"] != claim_value
    ]

    if contradictions:
        return {
            "verdict": "contradicted",
            "confidence": "low",
            "corroboratingSources": sorted(contradictions)
        }

    # Rule 3: fresh sources agreeing with claim
    matching = [
        source
        for source in fresh
        if source["value"] == claim_value
    ]

    # One representative per origin.
    # Lexicographically smallest ID wins.
    representatives = {}

    for source in matching:
        origin = source["origin"]

        if (
            origin not in representatives
            or source["id"] < representatives[origin]["id"]
        ):
            representatives[origin] = source

    reps = list(representatives.values())

    if len(reps) >= 2:

        types = {source["type"] for source in reps}

        confidence = "high" if len(types) >= 2 else "medium"

        return {
            "verdict": "supported",
            "confidence": confidence,
            "corroboratingSources": sorted(
                source["id"] for source in reps
            )
        }

    # Rule 4
    return {
        "verdict": "unverified",
        "confidence": "low",
        "corroboratingSources": []
    }
