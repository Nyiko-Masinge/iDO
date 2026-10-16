# iDO Reconciliation Platform

Local-first reconciliation software for bank and general-purpose data workflows. The initial foundation supports user roles, configurable two-dataset matching, exception review, and approval-gated completion.

## Requirements

- Python 3.11+
- Windows, macOS, or Linux

The first local version uses SQLite, so no database server is needed. PostgreSQL support remains a planned migration before shared or production deployment.

## Run locally

```powershell
py -3.11 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
$env:IDO_BOOTSTRAP_ADMIN_PASSWORD = "change-this-before-first-run"
uvicorn ido.main:app --reload
```

Open http://127.0.0.1:8000. On first start, iDO creates the local database and an `admin` user. The bootstrap password is read only when that account does not already exist; if the environment variable is unset, a generated password is printed in the server console. Database and uploaded files default to `./data` and can be relocated with `IDO_DATA_DIR`.

## First workflow

1. Sign in as the bootstrap administrator and create named users with the appropriate role.
2. Upload a left-side and right-side CSV or XLSX dataset.
3. Map fields across the two datasets, set an optional amount tolerance, and save the setup as a reusable workflow template if desired.
4. Review matched and unmatched rows. Any user can request approval; an administrator or approver can approve or reject it.

The generic matcher compares normalized values across mapped fields and optionally applies a numeric tolerance to different amount columns on each side. Matching is one-to-one and uses a keyed index rather than comparing every row pair. Results retain source row values and include an explanation. Imports accept CSV and XLSX (first worksheet); exports are CSV. Dashboard reporting currently includes aggregate match rate and daily run trends.

## Roles

- `admin`: user management, workflow and run management, and approvals.
- `approver`: review and decide approval requests.
- `analyst`: import, configure, run, and review reconciliations; request approval.
- `viewer`: read-only access.

## Structure

- `ido/main.py`: API, authentication, authorization, imports, workflows, analytics, and exports.
- `ido/database.py`: local database setup and schema.
- `ido/reconcile.py`: reusable matching engine.
- `ido/static/`: local web interface.

This is an initial implementation foundation, not yet a production deployment. Before handling sensitive or regulated financial data, add HTTPS and managed secrets for the target environment, retention controls, operational backups, and security review.
