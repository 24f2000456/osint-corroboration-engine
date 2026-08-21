from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

VALID_TYPES = {"dns", "ct_log", "registry", "archive", "scan"}


def parse_time(value: Any):
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
    # Rule 1: invalid
    if not isinstance(body, dict):
        return {
            "verdict": "invalid",
            "confidence": "low",
            "corroboratingSources": []
        }

    claim = body.get("claim")
    if not isinstance(claim, dict):
        return {
            "verdict": "invalid",
            "confidence": "low",
            "corroboratingSources": []
        }

    claim_value = claim.get("value")
    as_of = parse_time(body.get("asOf"))
    staleness_days = body.get("stalenessDays")
    sources = body.get("sources")

    if (
        not isinstance(claim_value, str)
        or as_of is None
        or isinstance(staleness_days, bool)
        or not isinstance(staleness_days, (int, float))
        or not isinstance(sources, list)
    ):
        return {
            "verdict": "invalid",
            "confidence": "low",
            "corroboratingSources": []
        }

    # Collect only valid + fresh sources
    fresh_sources = []

    for source in sources:
        if not isinstance(source, dict):
            continue

        required_strings = ["id", "origin", "value", "observedAt"]

        if any(not isinstance(source.get(k), str) for k in required_strings):
            continue

        if source.get("type") not in VALID_TYPES:
            continue

        observed_at = parse_time(source["observedAt"])
        if observed_at is None:
            continue

        # Future observations are not stale
        age_seconds = (as_of - observed_at).total_seconds()
        age_days = age_seconds / 86400

        if age_days <= staleness_days:
            fresh_sources.append(source)

    # Rule 2: authoritative contradiction
    contradicting = [
        s for s in fresh_sources
        if s.get("authoritative") is True
        and s["value"] != claim_value
    ]

    if contradicting:
        return {
            "verdict": "contradicted",
            "confidence": "low",
            "corroboratingSources": sorted(
                s["id"] for s in contradicting
            )
        }

    # Rule 3: sources agreeing with claim
    matching = [
        s for s in fresh_sources
        if s["value"] == claim_value
    ]

    # One representative per origin.
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
        distinct_types = {s["type"] for s in reps}

        confidence = (
            "high"
            if len(distinct_types) >= 2
            else "medium"
        )

        return {
            "verdict": "supported",
            "confidence": confidence,
            "corroboratingSources": sorted(
                s["id"] for s in reps
            )
        }

    # Rule 4
    return {
        "verdict": "unverified",
        "confidence": "low",
        "corroboratingSources": []
    }
