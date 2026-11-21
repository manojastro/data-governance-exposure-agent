"""Deterministic synthetic data estate generator.

Generates a complete simulated enterprise: warehouse catalog (schemas hr,
finance, sales, support, analytics, marketing + out-of-scope ops), an
object-storage zone, marts, principals (users/groups/roles/service accounts/AI
agents), grants, a policy baseline, lineage, shares, conflicting-permission
pairs and the legitimate-access test suite.

ALL VALUES ARE SYNTHETIC. Emails/phones/addresses/government-ID-like strings/
bank-like strings are fabricated formats generated here -- they never encode
real personal information (see SECURITY.md).

Planted violation scenarios (ground truth mirrored in evaluation/ground_truth.json):
  V1  overprivileged_finance_role_hr_*   Finance Analyst role granted entire HR schema
  V2  orphaned_grant_jdoe_contractor_..  grant referencing a deleted user
  V3a stale_elevated_access_bob_manager.. admin privilege unused 180 days
  V3b stale_access_carol_reed_..          read access unused 150 days
  V4  public_share_on_sensitive_company_wide_directory
  V5  external_share_restricted_partner_northwind_share
  V6  unmasked_pii_via_hr.vw_employee_directory
  V7  missing_classification_ops.etl_config / raw exports file
  V8a policy_drift_support_agents_sales_orders (medium)
  V8b overbroad_grant_marketing_team_sales_customers_write (high)
  V9  service_account_overaccess_etl_svc (hr/sales/marketing reads)
  V10 ai_agent_scope_violation_support_copilot / revenue_analyst_agent
  V11 sod_conflict_henry_adams_create_payment_approve_payment
  V12 credential_exposure_finance_analysts_ops.etl_config
  V13 stale_elevated_access_grace_park.. unused CAN_SHARE on restricted ledger

Usage:
    python -m simulator.generate_estate            # seed ./data/data_governance.db
    python -m simulator.generate_estate --seed 7   # different deterministic seed
"""
from __future__ import annotations

import argparse
import random
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.config import get_settings, resolve_database_url  # noqa: E402
from app.db import Base  # noqa: E402
from app.models import (  # noqa: E402
    Classification, ColumnDef, ConflictingPair, Dataset, EventRow,
    Grant, LegitimacyTest, LineageEdge, PolicyBaselineRule, Principal, Share,
    utcnow,
)


def make_engine(url: str | None = None):
    from sqlalchemy import create_engine

    resolved = resolve_database_url(url or get_settings().DATABASE_URL)
    connect_args = {"check_same_thread": False} if resolved.startswith("sqlite") else {}
    return create_engine(resolved, connect_args=connect_args, future=True)


# ------------------------------------------------------------------ pools ---
FIRST = ["Alex", "Jordan", "Taylor", "Morgan", "Casey", "Riley", "Quinn", "Avery",
         "Dakota", "Skyler"]
LAST = ["Example", "Sample", "Placeholder", "Faketown", "Testers", "Mockwell",
        "Dummyfield", "Simson"]
STREETS = ["Evergreen St", "Cedar Ave", "Maple Blvd", "Oak Rd", "Birch Lane"]


def fake_email(rng: random.Random, who: str) -> str:
    return f"{who.lower().replace(' ', '.')}@exampleCorp.invalid"


def fake_phone(rng: random.Random) -> str:
    return f"+1-555-{rng.randint(200, 999)}-{rng.randint(0, 9999):04d}"


def fake_gov_id(rng: random.Random) -> str:
    """Clearly-fake format in the 900 range (never a real SSN)."""
    return f"9{rng.randint(10, 99)}-{rng.randint(10, 99)}-{rng.randint(1000, 9999)}"


def fake_address(rng: random.Random) -> str:
    return f"{rng.randint(10, 999)} {rng.choice(STREETS).title()} Apt {rng.randint(1, 60)}"


def fmt_salary(rng: random.Random) -> str:
    return f"{rng.randrange(25000, 240000, step=500):,}"


def fake_bank(rng: random.Random) -> str:
    return "DE89 " + " ".join(str(rng.randint(1000, 9999)) for _ in range(4)) + str(rng.randint(10, 99))


def samples(col_key: str, n: int, rng: random.Random) -> list[str]:
    """Deterministic sample-value pool per column key."""
    if col_key == "email":
        return [fake_email(rng, f"{rng.choice(FIRST)} {rng.choice(LAST)}") for _ in range(n)]
    if col_key == "phone":
        return [fake_phone(rng) for _ in range(n)]
    if col_key == "gov_id":
        return [fake_gov_id(rng) for _ in range(n)]
    if col_key == "address":
        return [fake_address(rng) for _ in range(n)]
    if col_key == "salary":
        return [fmt_salary(rng) for _ in range(n)]
    if col_key == "bank":
        return [fake_bank(rng) for _ in range(n)]
    if col_key == "customer_id":
        return [f"CUS-{rng.randint(100000, 999999)}" for _ in range(n)]
    if col_key == "employee_id":
        return [f"EMP-{rng.randint(10000, 99999)}" for _ in range(n)]
    if col_key == "credential":
        return ["sk-live-" + "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
                                      for _ in range(24)),
                "aws_secret_access_key=AKIAIOSFODNN7FAKEKEY",
                "".join(rng.choice("ABCDEFabcdef0123456789+/") for _ in range(40))]
    if col_key == "free_text_email":
        base = fake_email(rng, f"{rng.choice(FIRST)} {rng.choice(LAST)}")
        return [f"Customer wrote from {base}: portal is down",
                f"Reply to {fake_email(rng, 'Sam Jones')} about ticket escalation",
                "No contact email on file"]
    if col_key == "arr_usd":
        return [str(rng.randrange(50000, 4000000, 10000)) for _ in range(n)]
    return []


def add_dataset(s, fqns: dict, *, fqn, schema, name="", store="warehouse",
                type_="table", level="internal", owner="", rows=0):
    d = Dataset(fqn=fqn, name=name or fqn.split(".")[-1], schema_name=schema,
                store=store, dataset_type=type_, intended_level=level,
                owner_group=owner, row_count=rows)
    s.add(d)
    s.flush()
    fqns[fqn] = d.id
    return d


def add_col(s, ds: Dataset, name, dtype="varchar", masked=False, pool=None,
            position=0):
    c = ColumnDef(dataset_id=ds.id, name=name, data_type=dtype, masked=masked,
                  sample_values=pool or [], position=position)
    s.add(c)
    return c


# ------------------------------------------------------------------ main ----

def generate(session: Session, seed: int = 42, wipe: bool = True) -> dict:
    rng = random.Random(seed)
    now = utcnow()

    def days_ago(n: int) -> datetime:
        return now - timedelta(days=n)

    if wipe:
        for table in reversed(Base.metadata.sorted_tables):
            session.execute(table.delete())
        session.flush()

    fqns: dict[str, int] = {}

    # ------------------------------------------------------------ catalog --
    hr_emp = add_dataset(s=session, fqns=fqns, fqn="hr.employees", schema="hr",
                         level="restricted", owner="hr_business_partners", rows=1240)
    for i, (nm, dt, masked, key) in enumerate([
            ("employee_id", "varchar", False, "employee_id"),
            ("full_name", "varchar", False, None),
            ("email", "varchar", True, "email"),
            ("phone", "varchar", True, "phone"),
            ("gov_id_like", "varchar", True, "gov_id"),
            ("salary", "decimal", True, "salary"),
            ("street_address", "varchar", True, "address"),
            ("hire_date", "date", False, None)]):
        add_col(session, hr_emp, nm, dt, masked=masked,
                pool=samples(key, 6, rng) if key else [], position=i)

    hr_dir = add_dataset(s=session, fqns=fqns, fqn="hr.employee_directory", schema="hr",
                         level="internal", owner="hr_business_partners", rows=1180)
    for i, (nm, key) in enumerate([("employee_id", "employee_id"), ("full_name", None),
                                   ("work_email", "email"), ("work_phone", "phone"),
                                   ("business_unit", None)]):
        add_col(session, hr_dir, nm, pool=samples(key, 5, rng) if key else [], position=i)

    vw_dir = add_dataset(s=session, fqns=fqns, fqn="hr.vw_employee_directory", schema="hr",
                         type_="view", level="internal", owner="hr_business_partners")
    for i, nm in enumerate(["employee_id", "full_name", "email", "phone", "business_unit"]):
        add_col(session, vw_dir, nm, position=i)  # view re-exposes raw names, UNMASKED

    vw_agg = add_dataset(s=session, fqns=fqns, fqn="hr.vw_salary_aggregate", schema="hr",
                         type_="view", level="confidential", owner="hr_business_partners")
    for i, nm in enumerate(["department", "headcount", "avg_salary"]):
        add_col(session, vw_agg, nm, "decimal" if "salary" in nm else "int",
                pool=[fmt_salary(rng) for _ in range(4)] if "salary" in nm else [], position=i)

    gl = add_dataset(s=session, fqns=fqns, fqn="finance.gl_lines", schema="finance",
                     level="confidential", owner="finance_controllers", rows=982000)
    for i, nm in enumerate(["gl_account", "amount", "cost_center", "posted_by_emp", "memo"]):
        add_col(session, gl, nm, "decimal" if nm == "amount" else "varchar",
                pool=[f"EMP-2{rng.randint(1000, 9999)}" for _ in range(4)] if nm == "posted_by_emp" else [],
                position=i)

    inv = add_dataset(s=session, fqns=fqns, fqn="finance.invoices", schema="finance",
                      level="confidential", owner="finance_ar_team", rows=45000)
    for i, (nm, key) in enumerate([("invoice_id", None), ("customer_id", "customer_id"),
                                   ("amount", None), ("currency", None), ("due_date", None)]):
        add_col(session, inv, nm, pool=samples(key, 5, rng) if key else [], position=i)

    pay = add_dataset(s=session, fqns=fqns, fqn="finance.payments", schema="finance",
                      level="restricted", owner="treasury_office", rows=12000)
    for i, nm in enumerate(["payment_id", "vendor", "amount", "created_by",
                            "approved_by", "status"]):
        add_col(session, pay, nm, position=i)

    ledger = add_dataset(s=session, fqns=fqns, fqn="finance.restricted_ledger",
                         schema="finance", level="restricted", owner="exec_comp_committee",
                         rows=42)
    for i, (nm, key) in enumerate([("exec_code", None), ("total_comp", "salary"),
                                   ("bank_ref", "bank"), ("plan_year", None)]):
        add_col(session, ledger, nm, pool=samples(key, 4, rng) if key else [], position=i)

    cust = add_dataset(s=session, fqns=fqns, fqn="sales.customers", schema="sales",
                       level="internal", owner="sales_ops", rows=3800)
    for i, (nm, key) in enumerate([("customer_id", "customer_id"), ("company_name", None),
                                   ("contact_email", "email"), ("contact_phone", "phone"),
                                   ("industry", None), ("arr_usd", "arr_usd")]):
        add_col(session, cust, nm, pool=samples(key, 5, rng) if key else [], position=i)

    orders = add_dataset(s=session, fqns=fqns, fqn="sales.orders", schema="sales",
                         level="internal", owner="sales_ops", rows=152000)
    for i, (nm, key) in enumerate([("order_id", None), ("customer_id", "customer_id"),
                                   ("order_total", None), ("status", None), ("region", None)]):
        add_col(session, orders, nm, "decimal" if nm == "order_total" else "varchar",
                pool=samples(key, 5, rng) if key else [], position=i)

    tickets = add_dataset(s=session, fqns=fqns, fqn="support.tickets", schema="support",
                          level="internal", owner="support_leads", rows=78000)
    for i, (nm, key) in enumerate([("ticket_id", None), ("customer_id", "customer_id"),
                                   ("subject", None), ("free_text_notes", "free_text_email")]):
        add_col(session, tickets, nm, pool=samples(key, 6, rng) if key else [], position=i)

    kb = add_dataset(s=session, fqns=fqns, fqn="support.kb_articles", schema="support",
                     level="public", owner="support_leads", rows=310)
    for i, nm in enumerate(["article_id", "title", "body", "author_emp_id"]):
        add_col(session, kb, nm, position=i)

    daily = add_dataset(s=session, fqns=fqns, fqn="analytics.daily_sales",
                        schema="analytics", level="public", owner="analytics_platform",
                        rows=5000)
    for i, nm in enumerate(["date", "region", "revenue_usd", "orders_count"]):
        add_col(session, daily, nm, position=i)

    mart360 = add_dataset(s=session, fqns=fqns, fqn="analytics.mart_customer_360",
                          schema="analytics", type_="mart", level="internal",
                          owner="analytics_platform", rows=3800)
    for i, nm in enumerate(["customer_id", "lifetime_value", "last_contact_email"]):
        add_col(session, mart360, nm, position=i)

    martfin = add_dataset(s=session, fqns=fqns, fqn="analytics.mart_fin_summary",
                          schema="analytics", type_="mart", level="confidential",
                          owner="analytics_platform", rows=220)
    for i, nm in enumerate(["month", "total_amount", "variance"]):
        add_col(session, martfin, nm, position=i)

    leads = add_dataset(s=session, fqns=fqns, fqn="marketing.leads", schema="marketing",
                        level="internal", owner="growth_team", rows=9500)
    for i, (nm, key) in enumerate([("lead_id", None), ("company_email", "email"),
                                   ("campaign", None), ("score", None)]):
        add_col(session, leads, nm, pool=samples(key, 5, rng) if key else [], position=i)

    camps = add_dataset(s=session, fqns=fqns, fqn="marketing.campaigns", schema="marketing",
                        level="internal", owner="growth_team", rows=140)
    for i, nm in enumerate(["campaign_id", "channel", "budget_usd", "start_date"]):
        add_col(session, camps, nm, position=i)

    etlcfg = add_dataset(s=session, fqns=fqns, fqn="ops.etl_config", schema="ops",
                         level="restricted", owner="data_platform", rows=18)
    for i, (nm, key) in enumerate([("config_key", None), ("config_value", "credential"),
                                   ("rotated_at", None)]):
        add_col(session, etlcfg, nm, pool=samples(key, 3, rng) if key else [], position=i)

    rawexp = add_dataset(s=session, fqns=fqns, store="object_storage",
                         fqn="s3://acme-lake/raw/hr_exports/employees.jsonl",
                         schema="raw_zone", type_="file", level="internal", rows=1240)
    for i, (nm, key) in enumerate([("record", "email"), ("export_date", None)]):
        pool = (samples("email", 2, rng) + samples("salary", 2, rng)
                + samples("employee_id", 2, rng)) if nm == "record" else []
        add_col(session, rawexp, nm, "json", pool=pool, position=i)

    curated = add_dataset(
        s=session, fqns=fqns, store="object_storage",
        fqn="s3://acme-lake/curated/marketing/campaign_results.parquet",
        schema="curated_zone", type_="file", level="public", rows=140)
    add_col(session, curated, "campaign_id", position=0)
    add_col(session, curated, "conversions", "int", position=1)

    # ---------------------------------------------------------- identities --
    def principal(kind, name, dept="", member_of=None, scope=None, active=True,
                  deleted_at=None, title=""):
        p = Principal(kind=kind, name=name, display_name=name.replace("_", " ").title(),
                      department=dept, title=title, active=active, deleted_at=deleted_at,
                      member_of=member_of or [], declared_task_scope=scope)
        session.add(p)
        return p

    principal("user", "alice_chen", "Finance", title="Financial Analyst")
    bob = principal("user", "bob_manager", "Finance", title="Finance Manager")
    carol = principal("user", "carol_reed", "Sales", title="Account Executive")
    dave = principal("user", "dave_kim", "Support", title="Support Specialist")
    erin = principal("user", "erin_wu", "HR", title="HR Business Partner")
    sofia = principal("user", "sofia_reyes", "HR", title="HR Generalist")
    frank = principal("user", "frank_meyer", "Marketing", title="Growth Marketer")
    tom = principal("user", "tom_baker", "Marketing", title="Campaign Manager")
    grace = principal("user", "grace_park", "Data Engineering", title="Data Engineer")
    henry = principal("user", "henry_adams", "Finance", title="Payroll Officer")
    principal("user", "jdoe_contractor", "External", active=False,
              deleted_at=days_ago(210), title="Ex-contractor (offboarded)")

    principal("group", "finance_analysts", "Finance", member_of=["finance_analyst_role"])
    principal("group", "hr_specialists", "HR", member_of=["hr_generalist_role"])
    principal("group", "support_agents", "Support", member_of=["support_read_role"])
    principal("group", "marketing_team", "Marketing")
    principal("group", "data_engineers", "Data Engineering")
    principal("group", "payroll_processors", "Finance")
    principal("group", "payroll_approvers", "Finance")
    principal("group", "business_viewers", "Analytics")

    principal("role", "finance_analyst_role", "Finance")
    principal("role", "hr_generalist_role", "HR")
    principal("role", "support_read_role", "Support")

    principal("service_account", "svc_etl", "Data Engineering", scope={
        "task": "nightly ELT finance + analytics loads",
        "allowed_assets": ["finance.*", "analytics.*"],
        "operations": ["read", "query"]})
    principal("service_account", "svc_reporting", "Data Engineering", scope={
        "task": "BI extract refresh for public dashboards",
        "allowed_assets": ["analytics.*"],
        "operations": ["query"]})

    principal("ai_agent", "support_copilot", "Support", scope={
        "task": "Answer support-ticket questions using the ticket knowledge base",
        "allowed_assets": ["support.tickets", "support.kb_articles"],
        "operations": ["read"], "max_sensitivity": "internal"})
    principal("ai_agent", "revenue_analyst_agent", "Finance", scope={
        "task": "Summarize revenue trends from daily sales",
        "allowed_assets": ["analytics.daily_sales"],
        "operations": ["read"], "max_sensitivity": "public"})

    # explicit flush: sessions may run with autoflush=False, and the
    # membership/grant helpers below query these rows back by name
    session.flush()

    for user, groups in [("alice_chen", ["finance_analysts"]),
                         ("bob_manager", ["finance_analysts", "business_viewers"]),
                         ("carol_reed", ["business_viewers"]),
                         ("dave_kim", ["support_agents"]),
                         ("erin_wu", ["hr_specialists"]),
                         ("sofia_reyes", ["hr_specialists"]),
                         ("frank_meyer", ["marketing_team"]),
                         ("tom_baker", ["marketing_team"]),
                         ("grace_park", ["data_engineers"]),
                         ("henry_adams", ["payroll_processors", "payroll_approvers"])]:
        p = session.query(Principal).filter(Principal.name == user).first()
        p.member_of = groups
    jdoe = session.query(Principal).filter(Principal.name == "jdoe_contractor").first()
    jdoe.member_of = []

    # ---------------------------------------------------------------- grants -
    def grant(pname, asset_kind, asset_ref, privilege, used_days=None,
              granted_days=300, source="seed"):
        p = session.query(Principal).filter(Principal.name == pname).first()
        g = Grant(principal_id=p.id, asset_kind=asset_kind, asset_ref=asset_ref,
                  privilege=privilege, granted_on=days_ago(granted_days),
                  last_used_at=days_ago(used_days) if used_days is not None else None,
                  grantor="iam_sync", source=source)
        session.add(g)
        return g

    # -- legitimate grants (each covered by the baseline below) --------------
    grant("finance_analysts", "schema", "finance.*", "read", used_days=1)
    grant("finance_analyst_role", "schema", "finance.*", "read", used_days=2)
    grant("finance_analyst_role", "dataset", "hr.vw_salary_aggregate", "read", used_days=28)
    grant("hr_specialists", "schema", "hr.*", "read", used_days=1)
    grant("hr_generalist_role", "schema", "hr.*", "read", used_days=3)
    grant("support_agents", "dataset", "support.tickets", "read", used_days=0)
    grant("support_read_role", "dataset", "support.tickets", "read", used_days=1)
    grant("support_read_role", "dataset", "support.kb_articles", "read", used_days=6)
    grant("marketing_team", "dataset", "marketing.leads", "read", used_days=2)
    grant("marketing_team", "dataset", "marketing.campaigns", "read", used_days=9)
    grant("data_engineers", "dataset", "ops.etl_config", "read", used_days=4)
    grant("data_engineers", "schema", "finance.*", "read", used_days=1)
    grant("svc_etl", "schema", "finance.*", "read", used_days=1)
    grant("svc_etl", "schema", "analytics.*", "query", used_days=1)
    grant("svc_reporting", "schema", "analytics.*", "query", used_days=2)
    grant("payroll_processors", "dataset", "finance.payments", "create_payment", used_days=12)
    grant("payroll_approvers", "dataset", "finance.payments", "approve_payment", used_days=120)
    grant("business_viewers", "dataset", "analytics.mart_customer_360", "read", used_days=3)
    grant("dave_kim", "dataset", "support.tickets", "read", used_days=10)
    grant("alice_chen", "dataset", "finance.invoices", "read", used_days=20)
    grant("support_copilot", "dataset", "support.tickets", "read", used_days=1)
    grant("support_copilot", "dataset", "support.kb_articles", "read", used_days=5)
    grant("revenue_analyst_agent", "dataset", "analytics.daily_sales", "read", used_days=2)

    # -- planted violations ---------------------------------------------------
    # V1 overprivileged role: entire HR schema for finance analysts
    grant("finance_analyst_role", "schema", "hr.*", "read", used_days=30, granted_days=260)
    # V2 orphaned permission (deleted contractor)
    grant("jdoe_contractor", "dataset", "finance.gl_lines", "read", used_days=400)
    # V3a stale elevated: admin privilege unused 180 days
    grant("bob_manager", "dataset", "analytics.mart_fin_summary", "admin", used_days=180)
    # V3b stale read access unused 150 days (NOT in baseline; consumed by stale detector)
    grant("carol_reed", "dataset", "sales.orders", "read", used_days=150)
    # V6 unmasked PII via view: support agents can read raw directory view
    grant("support_agents", "dataset", "hr.vw_employee_directory", "read", used_days=15)
    # V8a pure policy drift: internal target, no sensitive tags
    grant("support_agents", "dataset", "sales.orders", "read", used_days=45)
    # V8b drift onto PII-bearing dataset -> escalates to OVERBROAD_GRANT
    grant("marketing_team", "dataset", "sales.customers", "write", used_days=45)
    # V9 excessive service-account access (3 grants beyond declared scope;
    # used 70 days ago -> below the 90-day staleness cutoff, so no double-flag)
    grant("svc_etl", "schema", "hr.*", "read", used_days=70)
    grant("svc_etl", "schema", "sales.*", "read", used_days=70)
    grant("svc_etl", "schema", "marketing.*", "read", used_days=70)
    # V10 AI agent scope violations
    grant("support_copilot", "dataset", "sales.customers", "read", used_days=8)
    grant("support_copilot", "dataset", "hr.employees", "read", used_days=25)
    grant("support_copilot", "dataset", "finance.invoices", "read", used_days=30)
    grant("support_copilot", "schema", "analytics.*", "query", used_days=5)
    grant("support_copilot", "dataset", "analytics.mart_customer_360", "write", used_days=5)
    grant("revenue_analyst_agent", "dataset", "sales.orders", "read", used_days=14)
    grant("revenue_analyst_agent", "dataset", "hr.employees", "read", used_days=21)
    # V11 SoD conflict: same person creates AND approves payments (approver side staler)
    #     (membership-based; grants above already carry both privileges)
    # V12 credential exposure: finance analysts can read the ETL config table
    grant("finance_analysts", "dataset", "ops.etl_config", "read", used_days=15)
    # V13 unused elevated permission: CAN_SHARE on restricted ledger, unused 200 days
    grant("grace_park", "dataset", "finance.restricted_ledger", "share", used_days=200)

    # ---------------------------------------------------------------- shares -
    session.add_all([
        Share(share_name="company_wide_directory", dataset_fqn="hr.employee_directory",
              recipient="all_employees", is_public=True, restriction_level="internal"),
        Share(share_name="partner_northwind_share", dataset_fqn="finance.restricted_ledger",
              recipient="northwind-partners-llc", external=True,
              restriction_level="restricted"),
        # negatives (must NOT be flagged)
        Share(share_name="analytics_public_metrics", dataset_fqn="analytics.daily_sales",
              recipient="public", is_public=True, restriction_level="public"),
        Share(share_name="sales_customers_internal", dataset_fqn="sales.customers",
              recipient="marketing_team", external=False, restriction_level="internal"),
    ])

    # ---------------------------------------------------------------- lineage -
    session.add_all([
        LineageEdge(source_fqn="hr.employees", target_fqn="hr.vw_employee_directory"),
        LineageEdge(source_fqn="hr.employees", target_fqn="hr.vw_salary_aggregate"),
        LineageEdge(source_fqn="sales.customers", target_fqn="analytics.mart_customer_360"),
        LineageEdge(source_fqn="support.tickets", target_fqn="analytics.mart_customer_360"),
        LineageEdge(source_fqn="finance.gl_lines", target_fqn="analytics.mart_fin_summary"),
    ])

    # ------------------------------------------------------- baseline policy -
    BASELINE = [
        ("finance_analysts", "finance.*", "read", "Finance team day job"),
        ("finance_analyst_role", "finance.*", "read", "Finance role day job"),
        ("finance_analyst_role", "hr.vw_salary_aggregate", "read",
         "Monthly salary-aggregate reporting (aggregated view only)"),
        ("hr_specialists", "hr.*", "read", "HR business partners manage HR data"),
        ("hr_generalist_role", "hr.*", "read", "HR generalist day job"),
        ("support_agents", "support.tickets", "read", "Ticket lookup workflow"),
        ("support_agents", "support.kb_articles", "read", "KB authoring reference"),
        ("support_read_role", "support.tickets", "read", "Ticket queue access"),
        ("support_read_role", "support.kb_articles", "read", "KB lookup"),
        ("support_agents", "hr.vw_employee_directory", "read",
         "Ticket context via employee directory -- legitimate ONLY once the "
         "view's PII columns are masked (paired with V6 remediation)"),
        ("marketing_team", "marketing.leads", "read", "Campaign operations"),
        ("marketing_team", "marketing.campaigns", "read", "Campaign operations"),
        ("data_engineers", "ops.etl_config", "read", "Pipeline configuration duty"),
        ("data_engineers", "finance.*", "read", "Pipeline development"),
        ("svc_etl", "finance.*", "read", "Nightly ELT load"),
        ("svc_etl", "analytics.*", "query", "Mart build queries"),
        ("svc_reporting", "analytics.*", "query", "Dashboard refresh"),
        ("payroll_processors", "finance.payments", "create_payment",
         "Payroll processing (creation side only)"),
        ("payroll_approvers", "finance.payments", "approve_payment",
         "Payment approval (approval side only; SoD forbids combining)"),
        ("business_viewers", "analytics.mart_customer_360", "read", "Self-serve analytics"),
        ("dave_kim", "support.tickets", "read", "Day-job direct grant"),
        ("alice_chen", "finance.invoices", "read", "AR reconciliation duty"),
        ("support_copilot", "support.tickets", "read", "Declared agent task scope"),
        ("support_copilot", "support.kb_articles", "read", "Declared agent task scope"),
        ("revenue_analyst_agent", "analytics.daily_sales", "read", "Declared agent task scope"),
    ]
    for pname, pat, priv, just in BASELINE:
        session.add(PolicyBaselineRule(principal_name=pname, asset_pattern=pat,
                                       privilege=priv, justification=just,
                                       effect="allow"))

    # --------------------------------------------- separation-of-duties pairs -
    session.add(ConflictingPair(privilege_a="create_payment",
                                privilege_b="approve_payment",
                                rationale="Same principal must not create and "
                                          "approve payments (fraud controls)."))

    # ------------------------------------------------ legitimacy test suite --
    LEGIT_TESTS = [
        ("finance_analyst_monthly_salary_aggregate_report",
         "finance_analyst_role", "hr.vw_salary_aggregate", "read", True,
         "Monthly salary-aggregate report must keep working after HR schema-grant replacement."),
        ("finance_analyst_gl_review",
         "finance_analysts", "finance.gl_lines", "read", True,
         "General-ledger review is core finance work."),
        ("hr_specialist_day_job_read",
         "hr_specialists", "hr.employees", "read", True,
         "HR specialists must retain full HR schema access."),
        ("hr_generalist_day_job_read",
         "hr_generalist_role", "hr.employees", "read", True,
         "HR role access preserved."),
        ("support_agent_ticket_lookup",
         "support_agents", "support.tickets", "read", True,
         "Support ticket lookup must keep working."),
        ("support_kb_lookup",
         "support_read_role", "support.kb_articles", "read", True,
         "Knowledge-base lookup must keep working."),
        ("ai_support_copilot_declared_task",
         "support_copilot", "support.tickets", "read", True,
         "AI agent's DECLARED task datasets must still work after narrowing."),
        ("ai_support_copilot_kb_task",
         "support_copilot", "support.kb_articles", "read", True,
         "Declared KB task preserved."),
        ("ai_revenue_agent_declared_task",
         "revenue_analyst_agent", "analytics.daily_sales", "read", True,
         "Revenue agent's declared dataset preserved."),
        ("etl_service_account_pipeline",
         "svc_etl", "finance.gl_lines", "read", True,
         "Nightly ELT within declared scope must not break."),
        ("reporting_service_account_dashboard",
         "svc_reporting", "analytics.daily_sales", "query", True,
         "Public dashboard refresh preserved."),
        ("payroll_creation_side",
         "henry_adams", "finance.payments", "create_payment", True,
         "SoD fix removes approval side, creation side stays."),
        ("marketing_campaign_ops",
         "marketing_team", "marketing.campaigns", "read", True,
         "Campaign operations preserved after drift revokes."),
        ("engineer_etl_config_duty",
         "data_engineers", "ops.etl_config", "read", True,
         "Platform engineers keep config-table access."),
        ("viewer_mart_access",
         "business_viewers", "analytics.mart_customer_360", "read", True,
         "Business viewers keep mart access."),
    ]
    for name, prin, asset, op, allowed, note in LEGIT_TESTS:
        session.add(LegitimacyTest(name=name, principal_name=prin, asset_fqn=asset,
                                   operation=op, should_be_allowed_after=allowed,
                                   workflow_note=note))

    # ------------------------------------------- seeded classification labels -
    # Existing catalog tags (what a mature-but-imperfect org already has).
    # In-scope warehouse datasets also carry dataset-level markers; the two
    # OUT-OF-SCOPE assets (ops.etl_config, raw exports file) intentionally have
    # NO classifications -> MISSING_CLASSIFICATION findings.
    session.add(Classification(dataset_id=fqns["hr.employees"], tag="__level__restricted",
                               level="restricted", confidence=1.0, source="baseline"))
    session.add(Classification(column_id=session.query(ColumnDef).filter_by(
        dataset_id=fqns["hr.employees"], name="gov_id_like").first().id,
        tag="gov_id_like", level="restricted", confidence=0.97, source="manual"))
    session.add(Classification(dataset_id=fqns["finance.restricted_ledger"],
                               tag="__level__restricted", level="restricted",
                               confidence=1.0, source="baseline"))
    session.add(Classification(dataset_id=fqns["finance.payments"],
                               tag="__level__restricted", level="restricted",
                               confidence=1.0, source="baseline"))
    session.add(Classification(dataset_id=fqns["analytics.daily_sales"],
                               tag="__level__public", level="public",
                               confidence=1.0, source="baseline"))
    session.add(Classification(dataset_id=fqns["support.kb_articles"],
                               tag="__level__public", level="public",
                               confidence=1.0, source="baseline"))
    session.add(Classification(dataset_id=fqns["finance.invoices"],
                               tag="__level__confidential", level="confidential",
                               confidence=1.0, source="baseline"))
    session.add(Classification(
        dataset_id=fqns["s3://acme-lake/curated/marketing/campaign_results.parquet"],
        tag="__level__public", level="public", confidence=1.0, source="baseline"))

    session.add(EventRow(kind="estate_seeded",
                         message=f"Estate seeded deterministically (seed={seed})",
                         payload={"seed": seed}))
    session.commit()
    return {
        "datasets": len(fqns),
        "principals": session.query(Principal).count(),
        "grants": session.query(Grant).count(),
        "shares": session.query(Share).count(),
        "columns": session.query(ColumnDef).count(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed the synthetic governance estate")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--db", default=None, help="override DATABASE_URL")
    args = parser.parse_args()

    engine = make_engine(args.db)
    Base.metadata.create_all(engine)
    from sqlalchemy.orm import sessionmaker

    s = sessionmaker(bind=engine, future=True)()
    stats = generate(s, seed=args.seed)
    print(f"[simulator] seeded estate: {stats['datasets']} datasets, "
          f"{stats['principals']} principals (seed={args.seed})")


if __name__ == "__main__":
    main()
