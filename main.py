from datetime import datetime
from typing import Any

from fastapi import FastAPI

app = FastAPI()

VALID_TYPES = {
    "dns",
    "ct_log",
    "registry",
    "archive",
    "scan",
}


def invalid_response():
    return {
        "verdict": "invalid",
        "confidence": "low",
        "corroboratingSources": [],
    }


def parse_timestamp(value):
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
def corroborate(body: Any):

    # --------------------------------------------------
    # RULE 1: INVALID
    # --------------------------------------------------

    if not isinstance(body, dict):
        return invalid_response()

    claim = body.get("claim")

    if not isinstance(claim, dict):
        return invalid_response()

    claim_value = claim.get("value")

    if not isinstance(claim_value, str):
        return invalid_response()

    as_of = parse_timestamp(body.get("asOf"))

    if as_of is None:
        return invalid_response()

    staleness_days = body.get("stalenessDays")

    # bool is technically an int in Python, but must not
    # be accepted as a number here.
    if isinstance(staleness_days, bool):
        return invalid_response()

    if not isinstance(staleness_days, (int, float)):
        return invalid_response()

    sources = body.get("sources")

    if not isinstance(sources, list):
        return invalid_response()

    # --------------------------------------------------
    # KEEP ONLY VALID + FRESH SOURCES
    # --------------------------------------------------

    fresh_sources = []

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

        observed_at = parse_timestamp(source.get("observedAt"))

        if observed_at is None:
            continue

        age_days = (
            as_of - observed_at
        ).total_seconds() / 86400

        # Anything older than the window is stale.
        # Future observations are still fresh.
        if age_days <= staleness_days:
            fresh_sources.append(source)

    # --------------------------------------------------
    # RULE 2: AUTHORITATIVE CONTRADICTION
    # --------------------------------------------------

    contradicting = []

    for source in fresh_sources:

        if (
            source.get("authoritative") is True
            and source["value"] != claim_value
        ):
            contradicting.append(source["id"])

    if contradicting:
        return {
            "verdict": "contradicted",
            "confidence": "low",
            "corroboratingSources": sorted(contradicting),
        }

    # --------------------------------------------------
    # RULE 3: SUPPORTING SOURCES
    # --------------------------------------------------

    matching = [
        source
        for source in fresh_sources
        if source["value"] == claim_value
    ]

    # One representative per origin.
    # Smallest lexicographical ID wins.
    representatives = {}

    for source in matching:

        origin = source["origin"]

        if origin not in representatives:
            representatives[origin] = source

        elif source["id"] < representatives[origin]["id"]:
            representatives[origin] = source

    reps = list(representatives.values())

    if len(reps) >= 2:

        distinct_types = {
            source["type"]
            for source in reps
        }

        if len(distinct_types) >= 2:
            confidence = "high"
        else:
            confidence = "medium"

        return {
            "verdict": "supported",
            "confidence": confidence,
            "corroboratingSources": sorted(
                source["id"]
                for source in reps
            ),
        }

    # --------------------------------------------------
    # RULE 4: UNVERIFIED
    # --------------------------------------------------

    return {
        "verdict": "unverified",
        "confidence": "low",
        "corroboratingSources": [],
    }
