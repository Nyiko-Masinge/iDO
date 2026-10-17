import csv
import hashlib
import io
import json
import os
import re
import secrets
import zipfile
from decimal import Decimal
from datetime import date, datetime
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, File, Header, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .database import connect, init_db
from .reconcile import normalize, number, reconcile
from .security import password_hash, password_ok

ROLES = {"admin", "approver", "analyst", "viewer"}
ROLE_RANK = {"viewer": 0, "analyst": 1, "approver": 2, "admin": 3}

def audit(db, actor, action, entity, entity_id=None, details=None):
    db.execute("INSERT INTO audit_log(actor_id,action,entity_type,entity_id,details_json) VALUES(?,?,?,?,?)",
               (actor, action, entity, entity_id, json.dumps(details or {})))

@asynccontextmanager
async def lifespan(app):
    init_db()
    with connect() as db:
        if not db.execute("SELECT 1 FROM users WHERE username='admin'").fetchone():
            configured_password = os.getenv("IDO_BOOTSTRAP_ADMIN_PASSWORD")
            initial = configured_password or secrets.token_urlsafe(18)
            db.execute("INSERT INTO users(username,password_hash,role) VALUES(?,?, 'admin')", ("admin", password_hash(initial)))
            if not configured_password:
                print(f"iDO bootstrap administrator password (save it now): {initial}")
    yield

app = FastAPI(title="iDO Reconciliation Platform", version="0.1.0", lifespan=lifespan)
app.mount("/static", StaticFiles(directory="ido/static"), name="static")

class Login(BaseModel):
    username: str
    password: str

class NewUser(BaseModel):
    username: str = Field(min_length=3, max_length=80, pattern=r"^[a-zA-Z0-9_.@-]+$")
    password: str = Field(min_length=12, max_length=200)
    role: str

class RunInput(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    left_dataset_id: int
    right_dataset_id: int
    key_mappings: list[dict[str, str]] = Field(default_factory=list)
    amount_mapping: dict[str, str] | None = None
    # Backward-compatible fields for earlier saved frontend requests.
    keys: list[str] = Field(default_factory=list)
    amount_field: str | None = None
    tolerance: float = Field(default=0, ge=0)
    workflow_template_id: int | None = Field(default=None, ge=1)

class ApprovalDecision(BaseModel):
    decision: str
    comment: str = ""

class ResultFeedback(BaseModel):
    verdict: str
    corrected_left_index: int | None = Field(default=None, ge=0)
    corrected_right_index: int | None = Field(default=None, ge=0)
    comment: str = Field(default="", max_length=1000)

class WorkflowInput(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=500)
    key_mappings: list[dict[str, str]] = Field(default_factory=list)
    amount_mapping: dict[str, str] | None = None
    tolerance: float = Field(default=0, ge=0)

def current_user(authorization: str | None = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Sign in required")
    token_hash = hashlib.sha256(authorization[7:].encode()).hexdigest()
    with connect() as db:
        row = db.execute("SELECT u.id,u.username,u.role,u.active FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?", (token_hash,)).fetchone()
    if not row or not row["active"]:
        raise HTTPException(401, "Session expired or user disabled")
    return dict(row)

def require(min_role):
    def check(user=Depends(current_user)):
        if ROLE_RANK[user["role"]] < ROLE_RANK[min_role]:
            raise HTTPException(403, "Your role does not allow this action")
        return user
    return check

@app.get("/")
def home():
    return FileResponse("ido/static/index.html")

@app.get("/api/health")
def health():
    return {"status": "ok", "service": "ido"}

@app.post("/api/login")
def login(payload: Login):
    with connect() as db:
        user = db.execute("SELECT * FROM users WHERE username=? AND active=1", (payload.username,)).fetchone()
        if not user or not password_ok(payload.password, user["password_hash"]):
            raise HTTPException(401, "Invalid username or password")
        token = secrets.token_urlsafe(36)
        db.execute("INSERT INTO sessions(token_hash,user_id) VALUES(?,?)", (hashlib.sha256(token.encode()).hexdigest(), user["id"]))
        audit(db, user["id"], "sign_in", "user", user["id"])
        return {"token": token, "user": {"id": user["id"], "username": user["username"], "role": user["role"]}}

@app.post("/api/logout")
def logout(user=Depends(current_user), authorization: str = Header()):
    digest = hashlib.sha256(authorization[7:].encode()).hexdigest()
    with connect() as db:
        db.execute("DELETE FROM sessions WHERE token_hash=?", (digest,))
    return {"ok": True}

@app.get("/api/me")
def me(user=Depends(current_user)):
    return user

@app.get("/api/users")
def users(user=Depends(require("admin"))):
    with connect() as db:
        return [dict(r) for r in db.execute("SELECT id,username,role,active,created_at FROM users ORDER BY username")]

@app.post("/api/users")
def create_user(payload: NewUser, user=Depends(require("admin"))):
    if payload.role not in ROLES:
        raise HTTPException(400, "Unsupported role")
    with connect() as db:
        try:
            cur = db.execute("INSERT INTO users(username,password_hash,role) VALUES(?,?,?)", (payload.username, password_hash(payload.password), payload.role))
        except Exception as exc:
            if "UNIQUE" in str(exc):
                raise HTTPException(409, "Username already exists")
            raise
        audit(db, user["id"], "create_user", "user", cur.lastrowid, {"role": payload.role})
        return {"id": cur.lastrowid, "username": payload.username, "role": payload.role}

@app.post("/api/datasets")
async def upload_dataset(name: str, file: UploadFile = File(...), user=Depends(require("analyst"))):
    if not file.filename or not file.filename.lower().endswith((".csv", ".xlsx")):
        raise HTTPException(400, "Upload a CSV or XLSX file")
    raw = await file.read(25 * 1024 * 1024 + 1)
    if len(raw) > 25 * 1024 * 1024:
        raise HTTPException(413, "File exceeds the 25 MB local upload limit")
    try:
        if file.filename.lower().endswith(".xlsx"):
            from openpyxl import load_workbook
            workbook = load_workbook(io.BytesIO(raw), read_only=True, data_only=True)
            sheet = workbook.active
            iterator = sheet.iter_rows(values_only=True)
            headers = next(iterator, ())
            columns = [str(value).strip() if value is not None else "" for value in headers]
            rows = [dict(zip(columns, [value.isoformat() if isinstance(value, (date, datetime)) else value for value in values])) for values in iterator]
            rows = [{k: (str(v) if v is not None else "") for k, v in row.items()} for row in rows]
            workbook.close()
        else:
            text = raw.decode("utf-8-sig")
            reader = csv.DictReader(io.StringIO(text))
            columns = reader.fieldnames or []
            rows = list(reader)
    except (UnicodeDecodeError, csv.Error, ValueError, StopIteration, zipfile.BadZipFile) as exc:
        raise HTTPException(400, f"Unable to read CSV: {exc}")
    if not columns or not rows:
        raise HTTPException(400, "CSV must have a header and at least one data row")
    if any(not column for column in columns) or len({column.casefold() for column in columns}) != len(columns):
        raise HTTPException(400, "Column headers must be non-empty and unique (ignoring letter case)")
    if len(rows) > 100_000:
        raise HTTPException(400, "CSV exceeds the 100,000 row local limit")
    with connect() as db:
        cur = db.execute("INSERT INTO datasets(name,source_name,owner_id,columns_json,rows_json,row_count) VALUES(?,?,?,?,?,?)",
                         (name, file.filename, user["id"], json.dumps(columns), json.dumps(rows), len(rows)))
        audit(db, user["id"], "import_dataset", "dataset", cur.lastrowid, {"rows": len(rows), "source_name": file.filename})
        return {"id": cur.lastrowid, "name": name, "source_name": file.filename, "columns": columns, "row_count": len(rows)}

@app.get("/api/datasets")
def datasets(user=Depends(current_user)):
    with connect() as db:
        return [dict(r) for r in db.execute("SELECT id,name,source_name,columns_json,row_count,created_at FROM datasets ORDER BY id DESC")]

@app.get("/api/datasets/{dataset_id}/profile")
def dataset_profile(dataset_id: int, user=Depends(current_user)):
    with connect() as db:
        dataset = db.execute("SELECT * FROM datasets WHERE id=?", (dataset_id,)).fetchone()
    if not dataset:
        raise HTTPException(404, "Dataset not found")
    rows = json.loads(dataset["rows_json"])
    profiles = []
    for column in json.loads(dataset["columns_json"]):
        values = [str(row.get(column, "")).strip() for row in rows]
        populated = [value for value in values if value]
        numeric = sum(1 for value in populated if re.fullmatch(r"[-+]?\d[\d,]*(\.\d+)?", value))
        profiles.append({"column": column, "populated": len(populated), "missing": len(values) - len(populated),
                         "unique": len(set(populated)), "numeric_share": round(numeric / len(populated), 3) if populated else 0,
                         "sample_values": list(dict.fromkeys(populated))[:4]})
    return {"id": dataset["id"], "name": dataset["name"], "row_count": dataset["row_count"], "columns": profiles,
            "preview": rows[:5]}

@app.get("/api/runs")
def runs(user=Depends(current_user)):
    with connect() as db:
        rows = db.execute("""SELECT r.*, d1.name left_name,d2.name right_name,
          (SELECT COUNT(*) FROM results x WHERE x.run_id=r.id AND x.status='matched') matched,
          (SELECT COUNT(*) FROM results x WHERE x.run_id=r.id AND x.status!='matched') exceptions,
          a.status approval_status FROM runs r JOIN datasets d1 ON d1.id=r.left_dataset_id
          JOIN datasets d2 ON d2.id=r.right_dataset_id LEFT JOIN approvals a ON a.run_id=r.id ORDER BY r.id DESC""").fetchall()
    return [{**dict(r), "config": json.loads(r["config_json"])} for r in rows]

@app.post("/api/runs")
def create_run(payload: RunInput, user=Depends(require("analyst"))):
    with connect() as db:
        left = db.execute("SELECT * FROM datasets WHERE id=?", (payload.left_dataset_id,)).fetchone()
        right = db.execute("SELECT * FROM datasets WHERE id=?", (payload.right_dataset_id,)).fetchone()
        if not left or not right:
            raise HTTPException(404, "Dataset not found")
        left_rows, right_rows = json.loads(left["rows_json"]), json.loads(right["rows_json"])
        left_cols, right_cols = json.loads(left["columns_json"]), json.loads(right["columns_json"])
        mappings = payload.key_mappings or [{"left": k, "right": k} for k in payload.keys]
        amount_mapping = payload.amount_mapping or ({"left": payload.amount_field, "right": payload.amount_field} if payload.amount_field else None)
        if not mappings:
            raise HTTPException(400, "Select at least one field mapping")
        if any(m.get("left") not in left_cols or m.get("right") not in right_cols for m in mappings):
            raise HTTPException(400, "Every mapped field must exist in its selected dataset")
        if amount_mapping and (amount_mapping.get("left") not in left_cols or amount_mapping.get("right") not in right_cols):
            raise HTTPException(400, "Amount mapping fields must exist in their selected datasets")
        aliases = []
        if payload.workflow_template_id:
            template = db.execute("SELECT config_json FROM workflow_templates WHERE id=?", (payload.workflow_template_id,)).fetchone()
            if not template:
                raise HTTPException(404, "Workflow template not found")
            template_config = json.loads(template["config_json"])
            if mappings != template_config.get("key_mappings", []):
                raise HTTPException(400, "Selected field mappings differ from the chosen workflow template")
            aliases = template_config.get("aliases", [])
        config = {"key_mappings": mappings, "amount_mapping": amount_mapping, "tolerance": payload.tolerance, "aliases": aliases}
        cur = db.execute("INSERT INTO runs(name,left_dataset_id,right_dataset_id,config_json,workflow_template_id,status,created_by) VALUES(?,?,?,?,?,?,?)",
                         (payload.name, left["id"], right["id"], json.dumps(config), payload.workflow_template_id, "completed", user["id"]))
        run_id = cur.lastrowid
        results = reconcile(left_rows, right_rows, config)
        for item in results:
            db.execute("INSERT INTO results(run_id,left_index,right_index,status,score,explanation,left_json,right_json) VALUES(?,?,?,?,?,?,?,?)",
                       (run_id, item["left_index"], item["right_index"], item["status"], item["score"], item["explanation"], json.dumps(item["left"]) if item["left"] is not None else None, json.dumps(item["right"]) if item["right"] is not None else None))
        audit(db, user["id"], "run_reconciliation", "run", run_id, {"result_count": len(results)})
        return {"id": run_id, "name": payload.name, "status": "completed", "result_count": len(results)}

@app.get("/api/workflows")
def workflows(user=Depends(current_user)):
    with connect() as db:
        rows = db.execute("SELECT id,name,description,config_json,created_at,updated_at FROM workflow_templates ORDER BY name").fetchall()
    return [{**dict(row), "config": json.loads(row["config_json"])} for row in rows]

@app.post("/api/workflows")
def save_workflow(payload: WorkflowInput, user=Depends(require("analyst"))):
    if not payload.key_mappings:
        raise HTTPException(400, "A workflow needs at least one key mapping")
    if any(not item.get("left") or not item.get("right") for item in payload.key_mappings):
        raise HTTPException(400, "Each mapping needs left and right fields")
    config = {"key_mappings": payload.key_mappings, "amount_mapping": payload.amount_mapping, "tolerance": payload.tolerance}
    with connect() as db:
        cur = db.execute("INSERT INTO workflow_templates(name,description,config_json,created_by) VALUES(?,?,?,?)",
                         (payload.name, payload.description, json.dumps(config), user["id"]))
        audit(db, user["id"], "save_workflow", "workflow", cur.lastrowid)
        return {"id": cur.lastrowid, "name": payload.name, "description": payload.description, "config": config}

@app.get("/api/analytics")
def analytics(user=Depends(current_user)):
    with connect() as db:
        totals = db.execute("SELECT COUNT(*) runs, COALESCE(SUM(matched),0) matched, COALESCE(SUM(exceptions),0) exceptions FROM (SELECT r.id,SUM(CASE WHEN x.status='matched' THEN 1 ELSE 0 END) matched,SUM(CASE WHEN x.status!='matched' THEN 1 ELSE 0 END) exceptions FROM runs r LEFT JOIN results x ON x.run_id=r.id GROUP BY r.id)").fetchone()
        series = db.execute("SELECT substr(created_at,1,10) day,COUNT(*) runs FROM runs GROUP BY day ORDER BY day DESC LIMIT 30").fetchall()
        approvals = db.execute("SELECT status,COUNT(*) count FROM approvals GROUP BY status").fetchall()
    matched, exceptions = totals["matched"], totals["exceptions"]
    return {"runs": totals["runs"], "matched": matched, "exceptions": exceptions,
            "match_rate": round(matched / (matched + exceptions), 4) if matched + exceptions else 0,
            "daily_runs": [dict(r) for r in reversed(series)], "approvals": [dict(r) for r in approvals]}

def build_report(date_from=None, date_to=None, workflow_id=None, approval_status=None):
    clauses, params = [], []
    if date_from:
        clauses.append("substr(r.created_at,1,10)>=?")
        params.append(date_from)
    if date_to:
        clauses.append("substr(r.created_at,1,10)<=?")
        params.append(date_to)
    if workflow_id:
        clauses.append("r.workflow_template_id=?")
        params.append(workflow_id)
    if approval_status:
        clauses.append("COALESCE(a.status,'not_requested')=?")
        params.append(approval_status)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    with connect() as db:
        selected = db.execute("""SELECT r.id,r.name,r.created_at,r.status,r.workflow_template_id,r.config_json,
          d1.name left_dataset,d2.name right_dataset,w.name workflow_name,
          COALESCE(a.status,'not_requested') approval_status
          FROM runs r JOIN datasets d1 ON d1.id=r.left_dataset_id JOIN datasets d2 ON d2.id=r.right_dataset_id
          LEFT JOIN workflow_templates w ON w.id=r.workflow_template_id LEFT JOIN approvals a ON a.run_id=r.id""" + where + " ORDER BY r.id DESC", params).fetchall()
        data = []
        for run in selected:
            results = db.execute("SELECT status,score,left_json,right_json FROM results WHERE run_id=? ORDER BY id", (run["id"],)).fetchall()
            cfg = json.loads(run["config_json"])
            amount_mapping = cfg.get("amount_mapping") or ({"left": cfg["amount_field"], "right": cfg["amount_field"]} if cfg.get("amount_field") else None)
            counts = {"matched": 0, "unmatched_left": 0, "unmatched_right": 0}
            left_amounts = {"matched": Decimal(0), "unmatched": Decimal(0)}
            right_amounts = {"matched": Decimal(0), "unmatched": Decimal(0)}
            confidence_sum = 0.0
            for item in results:
                status = item["status"]
                counts[status] = counts.get(status, 0) + 1
                confidence_sum += item["score"]
                if amount_mapping:
                    left_row = json.loads(item["left_json"]) if item["left_json"] else None
                    right_row = json.loads(item["right_json"]) if item["right_json"] else None
                    bucket = "matched" if status == "matched" else "unmatched"
                    if left_row:
                        left_amounts[bucket] += number(left_row.get(amount_mapping["left"])) or Decimal(0)
                    if right_row:
                        right_amounts[bucket] += number(right_row.get(amount_mapping["right"])) or Decimal(0)
            matched, left_exc, right_exc = counts["matched"], counts["unmatched_left"], counts["unmatched_right"]
            total = matched + left_exc + right_exc
            variance = right_amounts["matched"] - left_amounts["matched"] if amount_mapping else None
            data.append({"id": run["id"], "name": run["name"], "created_at": run["created_at"],
                         "status": run["status"], "approval_status": run["approval_status"],
                         "workflow_id": run["workflow_template_id"], "workflow_name": run["workflow_name"] or "Ad hoc",
                         "left_dataset": run["left_dataset"], "right_dataset": run["right_dataset"],
                         "matched": matched, "unmatched_left": left_exc, "unmatched_right": right_exc,
                         "exceptions": left_exc + right_exc, "total_records": total,
                         "match_rate": matched / total if total else 0,
                         "average_score": confidence_sum / len(results) if results else 0,
                         "amount_mapping": amount_mapping,
                         "matched_left_amount": float(left_amounts["matched"]) if amount_mapping else None,
                         "matched_right_amount": float(right_amounts["matched"]) if amount_mapping else None,
                         "matched_variance": float(variance) if variance is not None else None,
                         "unmatched_left_amount": float(left_amounts["unmatched"]) if amount_mapping else None,
                         "unmatched_right_amount": float(right_amounts["unmatched"]) if amount_mapping else None})
    summary = {"runs": len(data), "matched": sum(x["matched"] for x in data),
               "exceptions": sum(x["exceptions"] for x in data), "unmatched_left": sum(x["unmatched_left"] for x in data),
               "unmatched_right": sum(x["unmatched_right"] for x in data), "records": sum(x["total_records"] for x in data)}
    summary["match_rate"] = summary["matched"] / summary["records"] if summary["records"] else 0
    amount_fields = ["matched_left_amount", "matched_right_amount", "matched_variance", "unmatched_left_amount", "unmatched_right_amount"]
    amount_runs = [run for run in data if run["amount_mapping"]]
    amount_totals = {"mapped_runs": len(amount_runs)}
    for field in amount_fields:
        amount_totals[field] = float(sum((Decimal(str(run[field])) for run in amount_runs if run[field] is not None), Decimal(0))) if amount_runs else None
    status_counts = {}
    daily = {}
    for run in data:
        status_counts[run["approval_status"]] = status_counts.get(run["approval_status"], 0) + 1
        day = run["created_at"][:10]
        bucket = daily.setdefault(day, {"day": day, "runs": 0, "matched": 0, "exceptions": 0})
        bucket["runs"] += 1
        bucket["matched"] += run["matched"]
        bucket["exceptions"] += run["exceptions"]
    return {"summary": summary, "amount_totals": amount_totals, "runs": data, "approval_breakdown": status_counts,
            "daily": [daily[day] for day in sorted(daily)],
            "amount_note": "Amount totals are shown only for runs with an amount mapping. Comparing side totals assumes the mapped fields use the same currency and sign convention."}

def validated_report_filters(date_from, date_to, workflow_id, approval_status):
    try:
        if date_from:
            date.fromisoformat(date_from)
        if date_to:
            date.fromisoformat(date_to)
    except ValueError:
        raise HTTPException(400, "Dates must use YYYY-MM-DD format")
    if date_from and date_to and date_from > date_to:
        raise HTTPException(400, "Start date must be on or before end date")
    allowed = {"not_requested", "pending", "approved", "rejected"}
    if approval_status and approval_status not in allowed:
        raise HTTPException(400, "Unsupported approval status filter")
    return date_from, date_to, workflow_id, approval_status

@app.get("/api/reports")
def reports(date_from: str | None = None, date_to: str | None = None,
            workflow_id: int | None = Query(default=None, ge=1), approval_status: str | None = None,
            user=Depends(current_user)):
    filters = validated_report_filters(date_from, date_to, workflow_id, approval_status)
    return build_report(*filters)

@app.get("/api/reports/export.csv")
def export_report(date_from: str | None = None, date_to: str | None = None,
                  workflow_id: int | None = Query(default=None, ge=1), approval_status: str | None = None,
                  user=Depends(current_user)):
    report = build_report(*validated_report_filters(date_from, date_to, workflow_id, approval_status))
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    fields = ["id", "name", "created_at", "workflow_name", "left_dataset", "right_dataset", "approval_status", "matched", "unmatched_left", "unmatched_right", "exceptions", "total_records", "match_rate", "average_score", "matched_left_amount", "matched_right_amount", "matched_variance", "unmatched_left_amount", "unmatched_right_amount"]
    writer.writerow(fields)
    for run in report["runs"]:
        writer.writerow([run.get(field) for field in fields])
    return StreamingResponse(iter([output.getvalue()]), media_type="text/csv", headers={"Content-Disposition": 'attachment; filename="ido-reconciliation-report.csv"'})

@app.get("/api/reports/exceptions.csv")
def export_report_exceptions(date_from: str | None = None, date_to: str | None = None,
                             workflow_id: int | None = Query(default=None, ge=1), approval_status: str | None = None,
                             user=Depends(current_user)):
    filters = validated_report_filters(date_from, date_to, workflow_id, approval_status)
    report = build_report(*filters)
    ids = [run["id"] for run in report["runs"]]
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["run_id", "run_name", "created_at", "approval_status", "exception_type", "left_record", "right_record", "explanation"])
    if ids:
        with connect() as db:
            for offset in range(0, len(ids), 500):
                chunk = ids[offset:offset + 500]
                placeholders = ",".join("?" for _ in chunk)
                rows = db.execute(f"SELECT r.id,r.name,r.created_at,a.status approval_status,x.status exception_type,x.left_json,x.right_json,x.explanation FROM results x JOIN runs r ON r.id=x.run_id LEFT JOIN approvals a ON a.run_id=r.id WHERE x.run_id IN ({placeholders}) AND x.status!='matched' ORDER BY r.id DESC,x.id", chunk).fetchall()
                for row in rows:
                    writer.writerow([row["id"], row["name"], row["created_at"], row["approval_status"] or "not_requested", row["exception_type"], row["left_json"] or "", row["right_json"] or "", row["explanation"]])
    return StreamingResponse(iter([output.getvalue()]), media_type="text/csv", headers={"Content-Disposition": 'attachment; filename="ido-reconciliation-exceptions.csv"'})

@app.get("/api/runs/{run_id}/export.csv")
def export_run(run_id: int, user=Depends(current_user)):
    with connect() as db:
        run = db.execute("SELECT name FROM runs WHERE id=?", (run_id,)).fetchone()
        if not run:
            raise HTTPException(404, "Run not found")
        rows = db.execute("SELECT status,score,explanation,left_json,right_json FROM results WHERE run_id=? ORDER BY id", (run_id,)).fetchall()
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["status", "score", "explanation", "left_record_json", "right_record_json"])
    for row in rows:
        writer.writerow([row["status"], row["score"], row["explanation"], row["left_json"] or "", row["right_json"] or ""])
    safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in run["name"])[:80]
    return StreamingResponse(iter([output.getvalue()]), media_type="text/csv", headers={"Content-Disposition": f'attachment; filename="ido-run-{run_id}-{safe_name}.csv"'})

@app.get("/api/runs/{run_id}/results")
def run_results(run_id: int, user=Depends(current_user)):
    with connect() as db:
        run = db.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
        if not run:
            raise HTTPException(404, "Run not found")
        rows = db.execute("""SELECT x.*,f.verdict my_feedback,
          (SELECT COUNT(*) FROM result_feedback f2 WHERE f2.result_id=x.id) feedback_count
          FROM results x LEFT JOIN result_feedback f ON f.result_id=x.id AND f.reviewer_id=?
          WHERE x.run_id=? ORDER BY x.id""", (user["id"], run_id)).fetchall()
    return [{**dict(r), "left": json.loads(r["left_json"]) if r["left_json"] else None,
             "right": json.loads(r["right_json"]) if r["right_json"] else None} for r in rows]

@app.post("/api/runs/{run_id}/results/{result_id}/feedback")
def submit_result_feedback(run_id: int, result_id: int, payload: ResultFeedback, user=Depends(require("analyst"))):
    allowed = {"confirmed_match", "false_match", "correct_pair", "unmatched_confirmed"}
    if payload.verdict not in allowed:
        raise HTTPException(400, "Unsupported feedback verdict")
    with connect() as db:
        result = db.execute("SELECT * FROM results WHERE id=? AND run_id=?", (result_id, run_id)).fetchone()
        run = db.execute("SELECT left_dataset_id,right_dataset_id,workflow_template_id,config_json FROM runs WHERE id=?", (run_id,)).fetchone()
        if not result or not run:
            raise HTTPException(404, "Run result not found")
        if payload.verdict == "confirmed_match" and result["status"] != "matched":
            raise HTTPException(400, "Only a matched result can be confirmed")
        if payload.verdict == "false_match" and result["status"] != "matched":
            raise HTTPException(400, "Only a matched result can be marked as a false match")
        if payload.verdict == "unmatched_confirmed" and result["status"] == "matched":
            raise HTTPException(400, "A matched result cannot be confirmed as unmatched")
        if payload.verdict == "correct_pair":
            if payload.corrected_left_index is None or payload.corrected_right_index is None:
                raise HTTPException(400, "A corrected pair needs both source row indexes")
            left = db.execute("SELECT row_count FROM datasets WHERE id=?", (run["left_dataset_id"],)).fetchone()
            right = db.execute("SELECT row_count FROM datasets WHERE id=?", (run["right_dataset_id"],)).fetchone()
            if payload.corrected_left_index >= left["row_count"] or payload.corrected_right_index >= right["row_count"]:
                raise HTTPException(400, "Corrected pair row index is outside its source dataset")
            if result["status"] != "unmatched_left" or result["left_index"] != payload.corrected_left_index:
                raise HTTPException(400, "Corrected pairs must start from this unmatched left-side result")
            if not db.execute("SELECT 1 FROM results WHERE run_id=? AND status='unmatched_right' AND right_index=?", (run_id, payload.corrected_right_index)).fetchone():
                raise HTTPException(400, "The selected right-side row is not an unmatched result in this run")
        db.execute("""INSERT INTO result_feedback(result_id,reviewer_id,verdict,corrected_left_index,corrected_right_index,comment)
          VALUES(?,?,?,?,?,?) ON CONFLICT(result_id,reviewer_id) DO UPDATE SET verdict=excluded.verdict,
          corrected_left_index=excluded.corrected_left_index,corrected_right_index=excluded.corrected_right_index,
          comment=excluded.comment,created_at=CURRENT_TIMESTAMP""",
          (result_id, user["id"], payload.verdict, payload.corrected_left_index, payload.corrected_right_index, payload.comment))
        audit(db, user["id"], "label_reconciliation_result", "result", result_id, {"verdict": payload.verdict})
        proposal_id = None
        if payload.verdict == "correct_pair" and run["workflow_template_id"]:
            left_rows = json.loads(db.execute("SELECT rows_json FROM datasets WHERE id=?", (run["left_dataset_id"],)).fetchone()["rows_json"])
            right_rows = json.loads(db.execute("SELECT rows_json FROM datasets WHERE id=?", (run["right_dataset_id"],)).fetchone()["rows_json"])
            left_row, right_row = left_rows[payload.corrected_left_index], right_rows[payload.corrected_right_index]
            mappings = json.loads(run["config_json"]).get("key_mappings", [])
            differences = [m for m in mappings if normalize(left_row.get(m["left"])) != normalize(right_row.get(m["right"]))]
            others_match = all(normalize(left_row.get(m["left"])) == normalize(right_row.get(m["right"])) for m in mappings if m not in differences)
            if len(differences) == 1 and others_match and normalize(left_row.get(differences[0]["left"])) and normalize(right_row.get(differences[0]["right"])):
                changed = differences[0]
                context = [{"left_field": m["left"], "right_field": m["right"],
                            "left_value": normalize(left_row.get(m["left"])), "right_value": normalize(right_row.get(m["right"]))}
                           for m in mappings if m is not changed]
                cur = db.execute("""INSERT OR IGNORE INTO learning_proposals(workflow_id,run_id,key_left_field,key_right_field,left_value,right_value,context_json,proposed_by)
                  VALUES(?,?,?,?,?,?,?,?)""", (run["workflow_template_id"], run_id, changed["left"], changed["right"],
                   str(left_row.get(changed["left"], "")), str(right_row.get(changed["right"], "")), json.dumps(context, sort_keys=True), user["id"]))
                proposal_id = cur.lastrowid if cur.rowcount else None
                if proposal_id:
                    audit(db, user["id"], "propose_learned_alias", "learning_proposal", proposal_id)
    return {"result_id": result_id, "verdict": payload.verdict, "learning_proposal_id": proposal_id}

@app.get("/api/learning/proposals")
def learning_proposals(user=Depends(current_user)):
    with connect() as db:
        rows = db.execute("""SELECT p.*,w.name workflow_name,u.username proposer
          FROM learning_proposals p JOIN workflow_templates w ON w.id=p.workflow_id
          JOIN users u ON u.id=p.proposed_by ORDER BY CASE p.status WHEN 'pending' THEN 0 ELSE 1 END,p.id DESC""").fetchall()
    return [{**dict(row), "context": json.loads(row["context_json"])} for row in rows]

@app.post("/api/learning/proposals/{proposal_id}/decision")
def decide_learning_proposal(proposal_id: int, payload: ApprovalDecision, user=Depends(require("approver"))):
    if payload.decision not in {"approved", "rejected"}:
        raise HTTPException(400, "Decision must be approved or rejected")
    with connect() as db:
        proposal = db.execute("SELECT * FROM learning_proposals WHERE id=?", (proposal_id,)).fetchone()
        if not proposal or proposal["status"] != "pending":
            raise HTTPException(409, "No pending learning proposal")
        if proposal["proposed_by"] == user["id"]:
            raise HTTPException(403, "The proposer cannot approve their own learning proposal")
        if payload.decision == "approved":
            workflow = db.execute("SELECT config_json FROM workflow_templates WHERE id=?", (proposal["workflow_id"],)).fetchone()
            config = json.loads(workflow["config_json"])
            alias = {"left_field": proposal["key_left_field"], "right_field": proposal["key_right_field"],
                     "left_value": proposal["left_value"], "right_value": proposal["right_value"],
                     "context": json.loads(proposal["context_json"])}
            aliases = config.setdefault("aliases", [])
            conflict = any(item["left_field"] == alias["left_field"] and item["right_field"] == alias["right_field"]
                           and normalize(item.get("right_value")) == normalize(alias["right_value"])
                           and item.get("context", []) == alias["context"]
                           and normalize(item.get("left_value")) != normalize(alias["left_value"]) for item in aliases)
            if conflict:
                raise HTTPException(409, "This source value already has a different approved alias in the workflow")
            if alias not in aliases:
                aliases.append(alias)
                db.execute("UPDATE workflow_templates SET config_json=?,updated_at=CURRENT_TIMESTAMP WHERE id=?", (json.dumps(config), proposal["workflow_id"]))
        db.execute("UPDATE learning_proposals SET status=?,decided_by=?,decision_comment=?,decided_at=CURRENT_TIMESTAMP WHERE id=?",
                   (payload.decision, user["id"], payload.comment, proposal_id))
        audit(db, user["id"], payload.decision + "_learning_proposal", "learning_proposal", proposal_id,
              {"workflow_id": proposal["workflow_id"], "comment": payload.comment})
    return {"proposal_id": proposal_id, "status": payload.decision}

@app.get("/api/learning/summary")
def learning_summary(user=Depends(current_user)):
    with connect() as db:
        row = db.execute("""SELECT COUNT(*) labels,
          SUM(CASE WHEN verdict IN ('confirmed_match','correct_pair') THEN 1 ELSE 0 END) positive,
          SUM(CASE WHEN verdict='false_match' THEN 1 ELSE 0 END) false_matches,
          SUM(CASE WHEN verdict='unmatched_confirmed' THEN 1 ELSE 0 END) confirmed_unmatched
          FROM result_feedback""").fetchone()
        reviewers = db.execute("SELECT COUNT(DISTINCT reviewer_id) reviewers FROM result_feedback").fetchone()["reviewers"]
        proposals = db.execute("SELECT SUM(CASE WHEN status='pending' THEN 1 ELSE 0 END) pending,SUM(CASE WHEN status='approved' THEN 1 ELSE 0 END) approved FROM learning_proposals").fetchone()
    total = row["labels"] or 0
    positive = row["positive"] or 0
    precision = positive / (positive + (row["false_matches"] or 0)) if positive + (row["false_matches"] or 0) else None
    return {"labels": total, "positive_examples": positive, "false_matches": row["false_matches"] or 0,
            "confirmed_unmatched": row["confirmed_unmatched"] or 0, "reviewers": reviewers,
            "pending_proposals": proposals["pending"] or 0, "approved_proposals": proposals["approved"] or 0,
            "observed_precision": round(precision, 4) if precision is not None else None,
            "automatic_learning_enabled": False,
            "message": "Reviewer labels are retained for evaluation. Learned matching behavior requires a reviewed proposal and explicit activation."}

@app.post("/api/runs/{run_id}/approval")
def request_approval(run_id: int, user=Depends(require("analyst"))):
    with connect() as db:
        run = db.execute("SELECT id,status FROM runs WHERE id=?", (run_id,)).fetchone()
        if not run:
            raise HTTPException(404, "Run not found")
        existing = db.execute("SELECT status FROM approvals WHERE run_id=?", (run_id,)).fetchone()
        if existing and existing["status"] == "pending":
            raise HTTPException(409, "Approval is already pending")
        db.execute("INSERT INTO approvals(run_id,requested_by,status) VALUES(?,?,'pending') ON CONFLICT(run_id) DO UPDATE SET requested_by=excluded.requested_by,status='pending',decided_by=NULL,comment=NULL,requested_at=CURRENT_TIMESTAMP,decided_at=NULL", (run_id, user["id"]))
        db.execute("UPDATE runs SET status='pending_approval' WHERE id=?", (run_id,))
        audit(db, user["id"], "request_approval", "run", run_id)
    return {"run_id": run_id, "approval_status": "pending"}

@app.post("/api/runs/{run_id}/decision")
def decide_approval(run_id: int, payload: ApprovalDecision, user=Depends(require("approver"))):
    if payload.decision not in {"approved", "rejected"}:
        raise HTTPException(400, "Decision must be approved or rejected")
    with connect() as db:
        approval = db.execute("SELECT * FROM approvals WHERE run_id=?", (run_id,)).fetchone()
        if not approval or approval["status"] != "pending":
            raise HTTPException(409, "No pending approval for this run")
        if approval["requested_by"] == user["id"]:
            raise HTTPException(403, "The requester cannot approve their own run")
        db.execute("UPDATE approvals SET status=?,decided_by=?,comment=?,decided_at=CURRENT_TIMESTAMP WHERE run_id=?", (payload.decision, user["id"], payload.comment, run_id))
        db.execute("UPDATE runs SET status=? WHERE id=?", (payload.decision, run_id))
        audit(db, user["id"], payload.decision + "_run", "run", run_id, {"comment": payload.comment})
    return {"run_id": run_id, "approval_status": payload.decision}

@app.get("/api/audit")
def audit_events(user=Depends(require("approver"))):
    with connect() as db:
        return [dict(r) for r in db.execute("SELECT a.*,u.username FROM audit_log a LEFT JOIN users u ON u.id=a.actor_id ORDER BY a.id DESC LIMIT 200")]
