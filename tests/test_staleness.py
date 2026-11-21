"""Staleness detector boundary tests: 90-day cutoff + elevated separation."""
from __future__ import annotations

from datetime import timedelta

from app.analysis.detection import STALE_DAYS, detect_all
from app.analysis.estate import load_snapshot
from app.models import Grant, Principal, utcnow


def _add_grant(session, principal_name, asset_ref, privilege, used_days):
    p = session.query(Principal).filter(Principal.name == principal_name).one()
    session.add(Grant(principal_id=p.id, asset_kind="dataset",
                      asset_ref=asset_ref, privilege=privilege,
                      granted_on=utcnow() - timedelta(days=200),
                      last_used_at=utcnow() - timedelta(days=used_days),
                      grantor="pytest", source="seed"))
    session.commit()


def _stale_keys(seeded):
    res = detect_all(load_snapshot(seeded))
    return {(f.type, f.principal_name, f.asset_ref)
            for f in res.findings if f.type.startswith("STALE")}


def test_cutoff_constant_is_90_days():
    assert STALE_DAYS == 90


def test_91_day_old_access_is_flagged(seeded):
    _add_grant(seeded, "dave_kim", "marketing.leads", "read", 91)
    keys = _stale_keys(seeded)
    assert ("STALE_ACCESS", "dave_kim", "marketing.leads") in keys


def test_89_day_old_access_is_not_flagged(seeded):
    _add_grant(seeded, "bob_manager", "support.kb_articles", "read", 89)
    keys = _stale_keys(seeded)
    assert not any(p == "bob_manager" and a == "support.kb_articles"
                   for (_t, p, a) in keys)


def test_elevated_privilege_gets_distinct_type(seeded):
    _add_grant(seeded, "bob_manager", "finance.gl_lines", "admin", 100)
    keys = _stale_keys(seeded)
    assert ("STALE_ELEVATED_ACCESS", "bob_manager", "finance.gl_lines") in keys
    # and it is NOT reported as plain stale access
    assert ("STALE_ACCESS", "bob_manager", "finance.gl_lines") not in keys


def test_seeded_planted_stale_findings_present(seeded):
    keys = _stale_keys(seeded)
    # carol: plain 150-day-old read
    assert ("STALE_ACCESS", "carol_reed", "sales.orders") in keys
    # bob: unused admin on the finance mart
    assert ("STALE_ELEVATED_ACCESS", "bob_manager",
            "analytics.mart_fin_summary") in keys
    # grace: unused CAN_SHARE on the restricted ledger
    assert ("STALE_ELEVATED_ACCESS", "grace_park",
            "finance.restricted_ledger") in keys


def test_fresh_access_never_flagged(seeded):
    keys = _stale_keys(seeded)
    assert not any(p == "dave_kim" for (_t, p, _a) in keys), \
        "dave_kim's grants are fresh (<=10 days) and must stay unflagged"
