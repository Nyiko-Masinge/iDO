import csv
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import zipfile
from datetime import date, datetime
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, File, Header, HTTPException, UploadFile
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .database import connect, init_db
from .reconcile import reconcile

ROLES = {"admin", "approver", "analyst", "viewer"}
ROLE_RANK = {"viewer": 0, "analyst": 1, "approver": 2, "admin": 3}

def password_hash(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 240_000).hex()
    return f"{salt}${digest}"

def password_ok(password, encoded):
    salt, _ = encoded.split("$", 1)
    return hmac.compare_digest(password_hash(password, salt), encoded)

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

class ApprovalDecision(BaseModel):
    decision: str
    comment: str = ""

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
        config = {"key_mappings": mappings, "amount_mapping": amount_mapping, "tolerance": payload.tolerance}
        cur = db.execute("INSERT INTO runs(name,left_dataset_id,right_dataset_id,config_json,status,created_by) VALUES(?,?,?,?,?,?)",
                         (payload.name, left["id"], right["id"], json.dumps(config), "completed", user["id"]))
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
        rows = db.execute("SELECT * FROM results WHERE run_id=? ORDER BY id", (run_id,)).fetchall()
    return [{**dict(r), "left": json.loads(r["left_json"]) if r["left_json"] else None,
             "right": json.loads(r["right_json"]) if r["right_json"] else None} for r in rows]

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
