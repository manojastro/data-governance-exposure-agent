# Data Governance Exposure Agent

Finds over-exposed data in a (simulated) enterprise estate and proposes the **smallest safe policy change**
that removes the exposure without breaking legitimate access. Changes are validated in a shadow policy
before anything is applied, and applying requires approval.

> Portfolio/POC build on a synthetic estate (`simulator/generate_estate.py`). Vendor adapters are stubs.

## Pipeline

A staged agent workflow (`backend/app/workflow/engine.py`) over a governed tool surface
(`backend/app/tools/governance_tools.py`):

| Stage | Agent / module | What it does |
|---|---|---|
| Scan + classify | `classification_agent`, `classifier/detectors.py` | Detects sensitive data in the estate |
| Access graph | `access_graph_agent`, `graph/access_graph.py` | Builds a NetworkX access graph, flags risky edges |
| Exposure | `exposure_agent` | Finds over-shared / over-privileged paths |
| AI identities | `ai_identity_agent` | Reviews access held by AI/service identities |
| Least privilege | `least_privilege_agent` | Proposes narrower grants |
| Drift | `drift_agent` | Grants vs baseline policy (90-day staleness cutoff, separation-of-duties checks) |
| Risk + remediation | `risk_agent`, `remediation_agent`, `analysis/minimality.py` | Smallest safe change, never blanket revokes |
| Validation | `validation_agent`, `analysis/shadow.py` | Shadow policy: exposure must drop, legitimate access must survive |

A remediation executor (`remediation/executor.py`) applies only approved proposals.

## API

FastAPI app (`backend/app/main.py`, `create_app()`): findings, scans, assets, shares, lineage, access graph,
AI identities, investigations, proposals, approvals (`/apply`), validations, risk register, tool-call audit,
legitimate-access tests, evaluation (`/evaluation/latest`), simulator, `/health`, `/readiness` and `/metrics`
(Prometheus).

LLM use is optional: `LLM_MODE=mock` (default behaviour) or an OpenAI-compatible endpoint via
`LLM_BASE_URL`, `LLM_API_KEY`, `LLM_MODEL`. Never commit keys.

## Run

```bash
pip install -r requirements.txt
python scripts/run_governance_demo.py          # end-to-end demo from the project root
cd backend && uvicorn app.main:app --reload     # API
```

The frontend is a static page in `frontend/` (`index.html`, `app.js`).

## Tests

```bash
pytest        # ~89 test functions: classifier, graph, minimality, shadow validation, separation of duties,
              # staleness, tools, agents, workflow, API, evaluation
```

Ground-truth labels for evaluation are in `evaluation/ground_truth.json`.
Note: generated SQLite databases are not committed; the simulator and demo recreate data.
