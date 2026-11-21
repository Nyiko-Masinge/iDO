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

Keep the server bound to localhost for this local build. Do not expose it to a LAN or the public internet: production use still needs HTTPS, managed secrets, MFA, deployment-level request limits, monitored backups, retention controls, and an independent security review.

If you lose a local user's password, stop the server and run `python -m ido.reset_admin` from this project directory. It prompts securely for the new password, invalidates that user's sessions, and keeps datasets and workflows.

## First workflow

1. Sign in as the bootstrap administrator and create named users with the appropriate role.
2. Upload a left-side and right-side CSV or XLSX dataset.
3. Map fields across the two datasets, set an optional amount tolerance, and save the setup as a reusable workflow template if desired.
4. Review matched and unmatched rows. Any user can request approval; an administrator or approver can approve or reject it.

The generic matcher compares normalized values across mapped fields and optionally applies a numeric tolerance to different amount columns on each side. Matching is one-to-one and uses a keyed index rather than comparing every row pair. Results retain source row values and include an explanation. Imports accept CSV and XLSX (first worksheet); exports are CSV. The Reports page filters runs by date, workflow, and approval state; builds charts by date, workflow, or approval state; supports run, match, exception, match-rate, confidence, and variance measures; saves per-user report views; and exports run summaries or exception details.

The Automation page supports daily and weekly schedules using saved workflows and already imported dataset snapshots. Each schedule can be run immediately or paused, can require approval, and records successful and failed executions. A detailed CSV is generated after each successful run under `data/automation_reports/`. Scheduled runs are checked while the local iDO server is running; they do not import fresh files. New source data still needs to be imported manually.

## Pilot readiness materials

- [Onboarding guide](docs/ONBOARDING_GUIDE.md)
- [Data handling and retention policy draft](docs/DATA_HANDLING_AND_RETENTION.md)
- [Controlled pilot plan](docs/PILOT_PLAN.md)

Reviewers can confirm matches, flag false matches, confirm exceptions, and record corrected pairs. These decisions form a persisted evaluation set and contribute to observed reviewed-match precision. A corrected pair can create a scoped alias proposal only when one configured key differs and the remaining mapped keys agree. A different approver must approve the proposal; accepted aliases are applied only to later runs that select the same saved workflow, and remain scoped to the agreeing context fields.

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

## Local security controls

- Passwords are PBKDF2 hashed; bearer sessions expire after 12 hours and are revoked on sign-out or password reset.
- Sign-in attempts are throttled after 10 failures for the same account and client address within a 15-minute window.
- Uploads are limited to 25 MB, 100,000 rows, 500 columns, 2,000,000 cells, and 100,000 characters per cell. XLSX archives are checked for oversized expansion before parsing.
- CSV exports neutralize spreadsheet formula prefixes. The local data directory and SQLite database use restrictive permissions where the operating system supports them.
- API responses are marked non-cacheable; security headers prevent framing, MIME sniffing, and unnecessary browser capabilities. The UI script is allowed through a content hash, generated controls use delegated click handling, and interactive API documentation is disabled.

These controls reduce common local risks; they do not make an application impossible to compromise. The current single-workspace SQLite design is intended for local evaluation and a controlled pilot, not yet for production financial data or internet-facing multi-tenant service.
