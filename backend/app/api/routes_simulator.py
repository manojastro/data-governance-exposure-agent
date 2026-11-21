"""Simulator seeding endpoint."""
from __future__ import annotations

from fastapi import APIRouter

from app.db import session_ctx
from app.schemas import SeedRequest

router = APIRouter(prefix="/api/v1")


@router.post("/simulator/seed")
def seed_estate(req: SeedRequest) -> dict:
    from simulator.generate_estate import generate

    with session_ctx() as s:
        stats = generate(s, seed=req.seed, wipe=req.reset)
        return {"seeded": True, "seed": req.seed, **stats}
