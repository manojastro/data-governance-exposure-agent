"""Probe: reproduce the pytest-context rollback TypeError."""
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT))

tmp = Path(tempfile.mkdtemp()) / "probe.db"
os.environ["DATABASE_URL"] = f"sqlite:///{tmp.as_posix()}"

from app.config import get_settings
get_settings.cache_clear()
from app.db import create_all, reset_engine, session_scope
reset_engine()
create_all()

s = session_scope()
from simulator.generate_estate import generate
print(generate(s, seed=42))
s.commit()

from app.llm.provider import MockLLMProvider
from app.workflow import engine as wf

inv = wf.create_investigation(s, title="probe", trigger="pytest")
summary = wf.run_detection_pipeline(s, inv, provider=MockLLMProvider())
s.commit()
print("pipeline:", {k: v for k, v in summary.items() if k != "by_type"})
print("targeted:", (inv.context or {}).get("targeted_scenario_keys"))

wf.approve(s, inv, approver="probe")
result = wf.apply_and_verify(s, inv)
print("status:", result.get("status"))
print("verification:", result.get("verification"))
print("skipped:", (result.get("skipped") or [])[:3])
