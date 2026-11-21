import asyncio
import base64
import csv
import hashlib
import io
import json
import os
import re
import secrets
import zipfile
from decimal import Decimal
from datetime import date, datetime, timedelta, timezone
from contextlib import asynccontextmanager, suppress

from fastapi import Depends, FastAPI, File, Header, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .database import DATA_DIR, connect, init_db
from .reconcile import normalize, number, reconcile
from .security import password_hash, password_ok
from pathlib import Path

ROLES = {"admin", "approver", "analyst", "viewer"}
ROLE_RANK = {"viewer": 0, "analyst": 1, "approver": 2, "admin": 3}
SESSION_MAX_AGE_HOURS = 12
MAX_UPLOAD_BYTES = 25 * 1024 * 1024
MAX_IMPORT_ROWS = 100_000
MAX_IMPORT_COLUMNS = 500
MAX_IMPORT_CELLS = 2_000_000
MAX_IMPORT_CELL_CHARS = 100_000
MAX_XLSX_UNCOMPRESSED_BYTES = 100 * 1024 * 1024
STATIC_DIR = Path(__file__).resolve().parent / "static"

def inline_script_csp_hash():
    page = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    match = re.search(r"<script>(.*?)</script>", page, re.DOTALL)
    if not match:
        return "'none'"
    digest = hashlib.sha256(match.group(1).encode("utf-8")).digest()
    return "'sha256-" + base64.b64encode(digest).decode("ascii") + "'"

SCRIPT_CSP_HASH = inline_script_csp_hash()

def audit(db, actor, action, entity, entity_id=None, details=None):
    db.execute("INSERT INTO audit_log(actor_id,action,entity_type,entity_id,details_json) VALUES(?,?,?,?,?)",
               (actor, action, entity, entity_id, json.dumps(details or {})))

@asynccontextmanager
async def lifespan(app):
    init_db()
    with connect() as db:
        db.execute(f"DELETE FROM sessions WHERE created_at < datetime('now', '-{SESSION_MAX_AGE_HOURS} hours')")
        db.execute("DELETE FROM login_attempts WHERE window_started_at < datetime('now', '-1 day') AND (locked_until IS NULL OR locked_until < datetime('now'))")
        db.execute("DELETE FROM import_staging WHERE created_at < datetime('now','-1 day')")
        if not db.execute("SELECT 1 FROM users WHERE username='admin'").fetchone():
            configured_password = os.getenv("IDO_BOOTSTRAP_ADMIN_PASSWORD")
            initial = configured_password or secrets.token_urlsafe(18)
            db.execute("INSERT INTO users(username,password_hash,role) VALUES(?,?, 'admin')", ("admin", password_hash(initial)))
            if not configured_password:
                print(f"iDO bootstrap administrator password (save it now): {initial}")
    worker = asyncio.create_task(automation_worker())
    try:
        yield
    finally:
        worker.cancel()
        with suppress(asyncio.CancelledError):
            await worker

app = FastAPI(title="iDO Reconciliation Platform", version="0.1.0", lifespan=lifespan,
              docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault("Content-Security-Policy", f"default-src 'self'; script-src 'self' {SCRIPT_CSP_HASH}; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'")
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response

class Login(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=200)

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
    comment: str = Field(default="", max_length=1000)

class ImportColumnMapping(BaseModel):
    source: str = Field(min_length=1, max_length=500)
    target: str = Field(default="", max_length=500)

class ImportCommit(BaseModel):
    preview_token: str = Field(min_length=20, max_length=100)
    columns: list[ImportColumnMapping] = Field(min_length=1, max_length=MAX_IMPORT_COLUMNS)

class ProfileUpdate(BaseModel):
    display_name: str = Field(default="", max_length=100)

class PreferencesUpdate(BaseModel):
    preferences: dict = Field(default_factory=dict)

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

class ReportViewInput(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    config: dict = Field(default_factory=dict)

class AutomationScheduleInput(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    workflow_id: int = Field(ge=1)
    left_dataset_id: int = Field(ge=1)
    right_dataset_id: int = Field(ge=1)
    cadence: str
    approval_required: bool = True

class AutomationScheduleStatus(BaseModel):
    enabled: bool

class AutomationScheduleUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    workflow_id: int | None = Field(default=None, ge=1)
    left_dataset_id: int | None = Field(default=None, ge=1)
    right_dataset_id: int | None = Field(default=None, ge=1)
    cadence: str | None = None
    approval_required: bool | None = None

def current_user(authorization: str | None = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Sign in required")
    token_hash = hashlib.sha256(authorization[7:].encode()).hexdigest()
    with connect() as db:
        row = db.execute(f"SELECT u.id,u.username,u.display_name,u.role,u.active FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.created_at>=datetime('now','-{SESSION_MAX_AGE_HOURS} hours')", (token_hash,)).fetchone()
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
    return FileResponse(STATIC_DIR / "index.html")

def validate_xlsx_archive(raw):
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            members = archive.infolist()
            if not members or len(members) > 10_000:
                raise ValueError("Spreadsheet archive has an invalid number of files")
            expanded = 0
            for member in members:
                expanded += member.file_size
                if expanded > MAX_XLSX_UNCOMPRESSED_BYTES:
                    raise ValueError("Spreadsheet expands beyond the 100 MB processing limit")
                if member.file_size > 1_000_000 and member.compress_size and member.file_size / member.compress_size > 100:
                    raise ValueError("Spreadsheet compression ratio exceeds the safe limit")
                if member.flag_bits & 0x1:
                    raise ValueError("Encrypted spreadsheets are not supported")
            if "[Content_Types].xml" not in archive.namelist() or "xl/workbook.xml" not in archive.namelist():
                raise ValueError("File is not a valid XLSX workbook")
    except zipfile.BadZipFile as exc:
        raise ValueError("File is not a valid XLSX workbook") from exc

def csv_safe(value):
    """Neutralize spreadsheet formula prefixes while preserving ordinary numeric values."""
    if not isinstance(value, str):
        return value
    probe = value.lstrip(" \t\r\n")
    if probe.startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + value
    return value

def write_csv_row(writer, values):
    writer.writerow([csv_safe(value) for value in values])

@app.get("/api/health")
def health():
    return {"status": "ok", "service": "ido"}

def login_attempt_key(client_ip, username):
    # Persist only a digest, not the source address or username used by the throttle.
    value = f"{client_ip or 'unknown'}\0{username.casefold()}".encode("utf-8", "replace")
    return hashlib.sha256(value).hexdigest()

@app.post("/api/login")
def login(payload: Login, request: Request):
    attempt_key = login_attempt_key(request.client.host if request.client else None, payload.username)
    invalid = False
    with connect() as db:
        lock = db.execute("SELECT locked_until,locked_until>datetime('now') is_locked FROM login_attempts WHERE attempt_key=?", (attempt_key,)).fetchone()
        if lock and lock["is_locked"]:
            raise HTTPException(429, "Too many sign-in attempts. Try again in 15 minutes.", headers={"Retry-After": "900"})
        user = db.execute("SELECT * FROM users WHERE username=? AND active=1", (payload.username,)).fetchone()
        # Verify a dummy hash for unknown accounts to reduce username timing leaks.
        valid = password_ok(payload.password, user["password_hash"] if user else "00000000000000000000000000000000$" + "0" * 64)
        if not user or not valid:
            db.execute("""INSERT INTO login_attempts(attempt_key,attempts,window_started_at,locked_until)
              VALUES(?,1,CURRENT_TIMESTAMP,NULL) ON CONFLICT(attempt_key) DO UPDATE SET
              attempts=CASE WHEN window_started_at<=datetime('now','-15 minutes') THEN 1 ELSE attempts+1 END,
              window_started_at=CASE WHEN window_started_at<=datetime('now','-15 minutes') THEN CURRENT_TIMESTAMP ELSE window_started_at END,
              locked_until=CASE WHEN (CASE WHEN window_started_at<=datetime('now','-15 minutes') THEN 1 ELSE attempts+1 END)>=10
                THEN datetime('now','+15 minutes') ELSE NULL END""", (attempt_key,))
            invalid = True
        else:
            db.execute("DELETE FROM login_attempts WHERE attempt_key=?", (attempt_key,))
            token = secrets.token_urlsafe(36)
            db.execute("INSERT INTO sessions(token_hash,user_id) VALUES(?,?)", (hashlib.sha256(token.encode()).hexdigest(), user["id"]))
            audit(db, user["id"], "sign_in", "user", user["id"])
    if invalid:
        raise HTTPException(401, "Invalid username or password")
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

@app.patch("/api/me/profile")
def update_profile(payload: ProfileUpdate, user=Depends(current_user)):
    display_name = payload.display_name.strip()
    with connect() as db:
        db.execute("UPDATE users SET display_name=? WHERE id=?", (display_name, user["id"]))
        audit(db, user["id"], "update_profile", "user", user["id"], {"display_name": display_name})
    return {"display_name": display_name}

DEFAULT_WORKSPACE_PREFERENCES = {"timezone": "Africa/Johannesburg", "currency": "ZAR", "date_format": "yyyy-mm-dd", "default_report_days": 30, "confirm_deletes": True}

@app.get("/api/me/preferences")
def get_preferences(user=Depends(current_user)):
    with connect() as db:
        row = db.execute("SELECT preferences_json FROM user_preferences WHERE user_id=?", (user["id"],)).fetchone()
    saved = json.loads(row["preferences_json"]) if row else {}
    return {**DEFAULT_WORKSPACE_PREFERENCES, **saved}

@app.patch("/api/me/preferences")
def update_preferences(payload: PreferencesUpdate, user=Depends(current_user)):
    allowed = set(DEFAULT_WORKSPACE_PREFERENCES)
    if set(payload.preferences) - allowed:
        raise HTTPException(400, "Unsupported workspace preference")
    with connect() as db:
        current = db.execute("SELECT preferences_json FROM user_preferences WHERE user_id=?", (user["id"],)).fetchone()
    existing = json.loads(current["preferences_json"]) if current else {}
    merged = {**DEFAULT_WORKSPACE_PREFERENCES, **existing, **payload.preferences}
    if merged["timezone"] not in {"Africa/Johannesburg", "UTC", "Europe/London", "America/New_York"}:
        raise HTTPException(400, "Choose a supported timezone")
    if merged["currency"] not in {"ZAR", "USD", "GBP", "EUR"}:
        raise HTTPException(400, "Choose a supported reporting currency")
    if merged["date_format"] not in {"yyyy-mm-dd", "dd/mm/yyyy", "mm/dd/yyyy"}:
        raise HTTPException(400, "Choose a supported date format")
    if type(merged["default_report_days"]) is not int or merged["default_report_days"] not in {7, 30, 90, 365}:
        raise HTTPException(400, "Default report period must be 7, 30, 90, or 365 days")
    if type(merged["confirm_deletes"]) is not bool:
        raise HTTPException(400, "Confirm-delete preference must be true or false")
    with connect() as db:
        db.execute("INSERT INTO user_preferences(user_id,preferences_json) VALUES(?,?) ON CONFLICT(user_id) DO UPDATE SET preferences_json=excluded.preferences_json,updated_at=CURRENT_TIMESTAMP", (user["id"], json.dumps(merged)))
        audit(db, user["id"], "update_workspace_preferences", "user", user["id"], merged)
    return merged

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
    name = name.strip()
    if not name or len(name) > 120:
        raise HTTPException(400, "Dataset name must be between 1 and 120 characters")
    raw = await file.read(MAX_UPLOAD_BYTES + 1)
    await file.close()
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "File exceeds the 25 MB local upload limit")
    try:
        if file.filename.lower().endswith(".xlsx"):
            from openpyxl import load_workbook
            validate_xlsx_archive(raw)
            workbook = load_workbook(io.BytesIO(raw), read_only=True, data_only=True, keep_links=False)
            sheet = workbook.active
            if sheet.max_column and sheet.max_column > MAX_IMPORT_COLUMNS:
                workbook.close()
                raise ValueError("Spreadsheet has more than 500 columns")
            if sheet.max_row and sheet.max_row > MAX_IMPORT_ROWS + 1:
                workbook.close()
                raise ValueError("Spreadsheet has more than 100,000 data rows")
            iterator = sheet.iter_rows(values_only=True)
            headers = next(iterator, ())
            columns = [str(value).strip() if value is not None else "" for value in headers]
            if len(columns) > MAX_IMPORT_COLUMNS:
                workbook.close()
                raise ValueError("Spreadsheet has more than 500 columns")
            rows = []
            total_cells = 0
            try:
                for values in iterator:
                    if len(rows) >= MAX_IMPORT_ROWS:
                        raise ValueError("Spreadsheet has more than 100,000 data rows")
                    if len(values) > MAX_IMPORT_COLUMNS:
                        raise ValueError("Spreadsheet has more than 500 columns")
                    total_cells += len(columns)
                    if total_cells > MAX_IMPORT_CELLS:
                        raise ValueError("Spreadsheet exceeds the 2,000,000 cell processing limit")
                    converted = [value.isoformat() if isinstance(value, (date, datetime)) else value for value in values]
                    if any(len(str(value)) > MAX_IMPORT_CELL_CHARS for value in converted if value is not None):
                        raise ValueError("A spreadsheet cell exceeds the 100,000 character limit")
                    rows.append({k: (str(v) if v is not None else "") for k, v in zip(columns, converted)})
            finally:
                workbook.close()
        else:
            text = raw.decode("utf-8-sig")
            csv.field_size_limit(MAX_IMPORT_CELL_CHARS)
            reader = csv.DictReader(io.StringIO(text))
            columns = [str(column).strip() if column is not None else "" for column in (reader.fieldnames or [])]
            if len(columns) > MAX_IMPORT_COLUMNS:
                raise ValueError("CSV has more than 500 columns")
            if len({column.casefold() for column in columns}) != len(columns):
                raise ValueError("Column headers must be unique, ignoring letter case")
            rows = []
            total_cells = 0
            for row in reader:
                if len(rows) >= MAX_IMPORT_ROWS:
                    raise ValueError("CSV has more than 100,000 data rows")
                values = list(row.values())
                if None in row or len(values) != len(columns) or any(len(value or "") > MAX_IMPORT_CELL_CHARS for value in values if value is not None):
                    raise ValueError("CSV row has too many fields or a cell exceeds the 100,000 character limit")
                total_cells += len(columns)
                if total_cells > MAX_IMPORT_CELLS:
                    raise ValueError("CSV exceeds the 2,000,000 cell processing limit")
                rows.append(dict(zip(columns, [value or "" for value in values])))
    except Exception as exc:
        raise HTTPException(400, str(exc) if isinstance(exc, ValueError) else "Unable to read CSV or XLSX file")
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

@app.post("/api/imports/preview")
async def preview_import(name: str, file: UploadFile = File(...), user=Depends(require("analyst"))):
    if not file.filename or not file.filename.lower().endswith((".csv", ".xlsx")):
        raise HTTPException(400, "Upload a CSV or XLSX file")
    name = name.strip()
    if not name or len(name) > 120:
        raise HTTPException(400, "Dataset name must be between 1 and 120 characters")
    raw = await file.read(MAX_UPLOAD_BYTES + 1)
    await file.close()
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "File exceeds the 25 MB local upload limit")
    invalid_rows, rows = [], []
    try:
        if file.filename.lower().endswith(".xlsx"):
            from openpyxl import load_workbook
            validate_xlsx_archive(raw)
            workbook = load_workbook(io.BytesIO(raw), read_only=True, data_only=True, keep_links=False)
            try:
                sheet = workbook.active
                if sheet.max_column and sheet.max_column > MAX_IMPORT_COLUMNS:
                    raise ValueError("Spreadsheet has more than 500 columns")
                if sheet.max_row and sheet.max_row > MAX_IMPORT_ROWS + 1:
                    raise ValueError("Spreadsheet has more than 100,000 data rows")
                iterator = sheet.iter_rows(values_only=True)
                columns = [str(v).strip() if v is not None else "" for v in next(iterator, ())]
                for line, values in enumerate(iterator, start=2):
                    if line > MAX_IMPORT_ROWS + 1:
                        raise ValueError("Spreadsheet has more than 100,000 data rows")
                    if len(values) > len(columns):
                        invalid_rows.append({"row": line, "reason": f"Row has {len(values)-len(columns)} extra cell(s)"})
                        continue
                    vals = [v.isoformat() if isinstance(v, (date, datetime)) else v for v in values]
                    if any(len(str(v)) > MAX_IMPORT_CELL_CHARS for v in vals if v is not None):
                        invalid_rows.append({"row": line, "reason": "Cell exceeds 100,000 characters"})
                        continue
                    if not any(str(v).strip() for v in vals if v is not None):
                        invalid_rows.append({"row": line, "reason": "Blank row"})
                        continue
                    rows.append({col: (str(vals[i]) if i < len(vals) and vals[i] is not None else "") for i, col in enumerate(columns)})
            finally:
                workbook.close()
        else:
            csv.field_size_limit(MAX_IMPORT_CELL_CHARS)
            reader = csv.reader(io.StringIO(raw.decode("utf-8-sig")))
            columns = [str(c).strip() if c is not None else "" for c in next(reader, [])]
            for line, values in enumerate(reader, start=2):
                if line > MAX_IMPORT_ROWS + 1:
                    raise ValueError("CSV has more than 100,000 data rows")
                if len(values) != len(columns):
                    invalid_rows.append({"row": line, "reason": f"Expected {len(columns)} cells, found {len(values)}"})
                    continue
                if any(len(v) > MAX_IMPORT_CELL_CHARS for v in values):
                    invalid_rows.append({"row": line, "reason": "Cell exceeds 100,000 characters"})
                    continue
                if not any(v.strip() for v in values):
                    invalid_rows.append({"row": line, "reason": "Blank row"})
                    continue
                rows.append(dict(zip(columns, values)))
        if not columns or not any(rows):
            raise ValueError("File must contain headers and at least one valid data row")
        if any(not c for c in columns) or len({c.casefold() for c in columns}) != len(columns):
            raise ValueError("Column headers must be non-empty and unique (ignoring letter case)")
        if sum(len(r) for r in rows) > MAX_IMPORT_CELLS:
            raise ValueError("File exceeds the 2,000,000 cell processing limit")
    except Exception as exc:
        raise HTTPException(400, str(exc) if isinstance(exc, ValueError) else "Unable to read CSV or XLSX file")
    token = secrets.token_urlsafe(36)
    with connect() as db:
        db.execute("INSERT INTO import_staging(token,owner_id,name,source_name,columns_json,rows_json,invalid_rows_json,invalid_count) VALUES(?,?,?,?,?,?,?,?)",
                   (token, user["id"], name, file.filename, json.dumps(columns), json.dumps(rows), json.dumps(invalid_rows[:200]), len(invalid_rows)))
    return {"preview_token": token, "name": name, "source_name": file.filename, "columns": columns,
            "sample_rows": rows[:5], "valid_row_count": len(rows), "invalid_count": len(invalid_rows), "invalid_rows": invalid_rows[:50]}

@app.post("/api/imports/commit")
def commit_import(payload: ImportCommit, user=Depends(require("analyst"))):
    with connect() as db:
        staged = db.execute("SELECT * FROM import_staging WHERE token=? AND owner_id=? AND created_at>=datetime('now','-1 day')",
                            (payload.preview_token, user["id"])).fetchone()
        if not staged:
            raise HTTPException(404, "Import preview expired or not found; preview the file again")
        source_columns, source_rows = json.loads(staged["columns_json"]), json.loads(staged["rows_json"])
        requested = {}
        for mapping in payload.columns:
            if mapping.source not in source_columns or mapping.source in requested:
                raise HTTPException(400, "Column mapping contains an unknown or repeated source field")
            target = mapping.target.strip()
            if target:
                requested[mapping.source] = target
        targets = list(requested.values())
        if not targets:
            raise HTTPException(400, "Keep and name at least one column")
        if len({target.casefold() for target in targets}) != len(targets):
            raise HTTPException(400, "Mapped column names must be unique")
        prepared = [{requested[source]: row.get(source, "") for source in requested} for row in source_rows]
        cur = db.execute("INSERT INTO datasets(name,source_name,owner_id,columns_json,rows_json,row_count) VALUES(?,?,?,?,?,?)",
                         (staged["name"], staged["source_name"], user["id"], json.dumps(targets), json.dumps(prepared), len(prepared)))
        dataset_id = cur.lastrowid
        audit(db, user["id"], "import_dataset", "dataset", dataset_id,
              {"rows": len(prepared), "invalid_rows_skipped": staged["invalid_count"], "source_name": staged["source_name"], "mapped_columns": len(targets)})
        db.execute("DELETE FROM import_staging WHERE token=?", (payload.preview_token,))
    return {"id": dataset_id, "name": staged["name"], "source_name": staged["source_name"], "columns": targets,
            "row_count": len(prepared), "invalid_rows_skipped": staged["invalid_count"]}

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

def automation_time(value=None):
    value = value or datetime.now(timezone.utc)
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

def next_automation_time(cadence, from_time=None):
    delta = timedelta(days=1 if cadence == "daily" else 7)
    value = from_time or datetime.now(timezone.utc)
    return automation_time(value + delta)

def create_automation_report(run_id, execution_id):
    with connect() as db:
        rows = db.execute("SELECT status,score,explanation,left_json,right_json FROM results WHERE run_id=? ORDER BY id", (run_id,)).fetchall()
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    write_csv_row(writer, ["status", "score", "explanation", "left_record_json", "right_record_json"])
    for row in rows:
        write_csv_row(writer, [row["status"], row["score"], row["explanation"], row["left_json"] or "", row["right_json"] or ""])
    folder = DATA_DIR / "automation_reports"
    folder.mkdir(parents=True, exist_ok=True)
    filename = f"execution-{execution_id}.csv"
    target = folder / filename
    target.write_text(output.getvalue(), encoding="utf-8-sig", newline="")
    try:
        target.chmod(0o600)
    except OSError:
        pass  # Windows permissions are managed by the local account ACL.
    return filename

def run_automation_schedule(schedule_id, trigger_type="scheduled", triggered_by=None):
    with connect() as db:
        schedule = db.execute("SELECT * FROM automation_schedules WHERE id=?", (schedule_id,)).fetchone()
        if not schedule:
            return {"status": "failed", "message": "Schedule not found"}
        owner_id = schedule["owner_id"]
        cur = db.execute("INSERT INTO automation_executions(schedule_id,triggered_by,trigger_type,status) VALUES(?,?,?,'running')",
                         (schedule_id, triggered_by or owner_id, trigger_type))
        execution_id = cur.lastrowid
        if trigger_type == "scheduled":
            db.execute("UPDATE automation_schedules SET last_run_at=?,next_run_at=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",
                       (automation_time(), next_automation_time(schedule["cadence"]), schedule_id))
    run_id = None
    try:
        with connect() as db:
            schedule = db.execute("SELECT * FROM automation_schedules WHERE id=?", (schedule_id,)).fetchone()
            workflow = db.execute("SELECT config_json,name FROM workflow_templates WHERE id=?", (schedule["workflow_id"],)).fetchone()
            left = db.execute("SELECT * FROM datasets WHERE id=?", (schedule["left_dataset_id"],)).fetchone()
            right = db.execute("SELECT * FROM datasets WHERE id=?", (schedule["right_dataset_id"],)).fetchone()
            if not workflow or not left or not right:
                raise ValueError("A selected workflow or dataset is no longer available")
            owner = db.execute("SELECT active FROM users WHERE id=?", (owner_id,)).fetchone()
            if not owner or not owner["active"]:
                raise ValueError("Schedule owner is inactive")
            config = json.loads(workflow["config_json"])
            mappings = config.get("key_mappings", [])
            left_columns, right_columns = json.loads(left["columns_json"]), json.loads(right["columns_json"])
            if not mappings or any(m.get("left") not in left_columns or m.get("right") not in right_columns for m in mappings):
                raise ValueError("Workflow fields do not match the selected datasets")
            amount_mapping = config.get("amount_mapping")
            if amount_mapping and (amount_mapping.get("left") not in left_columns or amount_mapping.get("right") not in right_columns):
                raise ValueError("Workflow amount fields do not match the selected datasets")
            left_rows, right_rows = json.loads(left["rows_json"]), json.loads(right["rows_json"])
            config["aliases"] = config.get("aliases", [])
            results = reconcile(left_rows, right_rows, config)
            run_name = f"{schedule['name'][:72]} · {datetime.now().strftime('%Y-%m-%d %H:%M')}"
            run_status = "pending_approval" if schedule["approval_required"] else "completed"
            cur = db.execute("INSERT INTO runs(name,left_dataset_id,right_dataset_id,config_json,workflow_template_id,status,created_by) VALUES(?,?,?,?,?,?,?)",
                             (run_name, left["id"], right["id"], json.dumps(config), schedule["workflow_id"], run_status, owner_id))
            run_id = cur.lastrowid
            for item in results:
                db.execute("INSERT INTO results(run_id,left_index,right_index,status,score,explanation,left_json,right_json) VALUES(?,?,?,?,?,?,?,?)",
                           (run_id, item["left_index"], item["right_index"], item["status"], item["score"], item["explanation"], json.dumps(item["left"]) if item["left"] is not None else None, json.dumps(item["right"]) if item["right"] is not None else None))
            if schedule["approval_required"]:
                db.execute("INSERT INTO approvals(run_id,requested_by,status) VALUES(?,?,'pending')", (run_id, owner_id))
            audit(db, triggered_by or owner_id, "automation_run", "run", run_id,
                  {"schedule_id": schedule_id, "execution_id": execution_id, "trigger_type": trigger_type, "result_count": len(results)})
        report_file = create_automation_report(run_id, execution_id)
        with connect() as db:
            db.execute("UPDATE automation_executions SET run_id=?,status='succeeded',message=?,report_file=?,finished_at=CURRENT_TIMESTAMP WHERE id=?",
                       (run_id, "Approval requested" if schedule["approval_required"] else "Run completed", report_file, execution_id))
        return {"id": execution_id, "run_id": run_id, "status": "succeeded", "report_file": report_file}
    except Exception as exc:
        message = str(exc)[:1000] or "Automation failed"
        error_code = "AUTOMATION_VALIDATION" if isinstance(exc, ValueError) else "AUTOMATION_ERROR"
        with connect() as db:
            db.execute("UPDATE automation_executions SET run_id=?,status='failed',message=?,error_code=?,finished_at=CURRENT_TIMESTAMP WHERE id=?",
                       (run_id, message, error_code, execution_id))
            audit(db, triggered_by or owner_id, "automation_failed", "automation_execution", execution_id,
                  {"schedule_id": schedule_id, "message": message})
        return {"id": execution_id, "run_id": run_id, "status": "failed", "error_code": error_code, "message": message}

def process_due_automation_schedules():
    now = automation_time()
    with connect() as db:
        schedule_ids = [row["id"] for row in db.execute("SELECT id FROM automation_schedules WHERE enabled=1 AND next_run_at<=? ORDER BY next_run_at,id", (now,)).fetchall()]
    for schedule_id in schedule_ids:
        run_automation_schedule(schedule_id, "scheduled")

async def automation_worker():
    while True:
        try:
            await asyncio.to_thread(process_due_automation_schedules)
        except Exception as exc:
            print(f"iDO automation scheduler cycle failed: {exc}")
        await asyncio.sleep(20)

@app.get("/api/automation/schedules")
def automation_schedules(user=Depends(current_user)):
    with connect() as db:
        rows = db.execute("""SELECT s.id,s.owner_id,u.username owner_name,s.name,s.workflow_id,w.name workflow_name,
          s.left_dataset_id,d1.name left_dataset,s.right_dataset_id,d2.name right_dataset,s.cadence,
          s.approval_required,s.enabled,s.next_run_at,s.last_run_at,s.created_at,s.updated_at,
          (SELECT status FROM automation_executions e WHERE e.schedule_id=s.id ORDER BY e.id DESC LIMIT 1) last_status,
          (SELECT message FROM automation_executions e WHERE e.schedule_id=s.id ORDER BY e.id DESC LIMIT 1) last_message,
          (SELECT COUNT(*) FROM automation_executions e WHERE e.schedule_id=s.id) execution_count
          FROM automation_schedules s JOIN users u ON u.id=s.owner_id JOIN workflow_templates w ON w.id=s.workflow_id
          JOIN datasets d1 ON d1.id=s.left_dataset_id JOIN datasets d2 ON d2.id=s.right_dataset_id WHERE s.archived=0 ORDER BY s.id DESC""").fetchall()
    return [dict(row) for row in rows]

@app.get("/api/automation/executions")
def automation_executions(user=Depends(current_user)):
    with connect() as db:
        rows = db.execute("""SELECT e.id,e.schedule_id,s.name schedule_name,e.run_id,e.trigger_type,e.status,e.message,
          e.triggered_by,COALESCE(NULLIF(u.display_name,''),u.username,'System') triggered_by_name,
          s.owner_id schedule_owner_id,e.error_code,
          e.started_at,e.finished_at,CASE WHEN e.report_file IS NULL THEN 0 ELSE 1 END has_report,
          r.name run_name,(SELECT COUNT(*) FROM results x WHERE x.run_id=e.run_id AND x.status='matched') matched,
          (SELECT COUNT(*) FROM results x WHERE x.run_id=e.run_id AND x.status!='matched') exceptions
          FROM automation_executions e LEFT JOIN automation_schedules s ON s.id=e.schedule_id
          LEFT JOIN users u ON u.id=e.triggered_by
          LEFT JOIN runs r ON r.id=e.run_id ORDER BY e.id DESC LIMIT 100""").fetchall()
    return [dict(row) for row in rows]

@app.post("/api/automation/schedules")
def create_automation_schedule(payload: AutomationScheduleInput, user=Depends(require("analyst"))):
    name = payload.name.strip()
    if not name:
        raise HTTPException(400, "Schedule name cannot be blank")
    if payload.cadence not in {"daily", "weekly"}:
        raise HTTPException(400, "Schedule frequency must be daily or weekly")
    if payload.left_dataset_id == payload.right_dataset_id:
        raise HTTPException(400, "Choose two different datasets")
    with connect() as db:
        workflow = db.execute("SELECT config_json FROM workflow_templates WHERE id=?", (payload.workflow_id,)).fetchone()
        left = db.execute("SELECT columns_json FROM datasets WHERE id=?", (payload.left_dataset_id,)).fetchone()
        right = db.execute("SELECT columns_json FROM datasets WHERE id=?", (payload.right_dataset_id,)).fetchone()
        if not workflow or not left or not right:
            raise HTTPException(404, "Workflow or dataset not found")
        config = json.loads(workflow["config_json"])
        left_columns, right_columns = json.loads(left["columns_json"]), json.loads(right["columns_json"])
        mappings = config.get("key_mappings", [])
        amount_mapping = config.get("amount_mapping")
        if not mappings or any(m.get("left") not in left_columns or m.get("right") not in right_columns for m in mappings):
            raise HTTPException(400, "The saved workflow fields do not match the selected datasets")
        if amount_mapping and (amount_mapping.get("left") not in left_columns or amount_mapping.get("right") not in right_columns):
            raise HTTPException(400, "The saved workflow amount fields do not match the selected datasets")
        next_run = next_automation_time(payload.cadence)
        cur = db.execute("INSERT INTO automation_schedules(owner_id,name,workflow_id,left_dataset_id,right_dataset_id,cadence,approval_required,next_run_at) VALUES(?,?,?,?,?,?,?,?)",
                         (user["id"], name, payload.workflow_id, payload.left_dataset_id, payload.right_dataset_id, payload.cadence, int(payload.approval_required), next_run))
        audit(db, user["id"], "create_automation_schedule", "automation_schedule", cur.lastrowid,
              {"cadence": payload.cadence, "workflow_id": payload.workflow_id, "approval_required": payload.approval_required})
        return {"id": cur.lastrowid, "name": name, "next_run_at": next_run, "enabled": True}

@app.patch("/api/automation/schedules/{schedule_id}")
def update_automation_schedule(schedule_id: int, payload: AutomationScheduleUpdate, user=Depends(require("analyst"))):
    with connect() as db:
        schedule = db.execute("SELECT * FROM automation_schedules WHERE id=? AND archived=0", (schedule_id,)).fetchone()
        if not schedule:
            raise HTTPException(404, "Automation schedule not found")
        if schedule["owner_id"] != user["id"] and user["role"] != "admin":
            raise HTTPException(403, "Only the schedule owner or an administrator can edit it")
        name = (payload.name if payload.name is not None else schedule["name"]).strip()
        workflow_id = payload.workflow_id if payload.workflow_id is not None else schedule["workflow_id"]
        left_id = payload.left_dataset_id if payload.left_dataset_id is not None else schedule["left_dataset_id"]
        right_id = payload.right_dataset_id if payload.right_dataset_id is not None else schedule["right_dataset_id"]
        cadence = payload.cadence if payload.cadence is not None else schedule["cadence"]
        approval_required = int(payload.approval_required if payload.approval_required is not None else schedule["approval_required"])
        if not name or cadence not in {"daily", "weekly"} or left_id == right_id:
            raise HTTPException(400, "Provide a name, valid frequency, and two different datasets")
        workflow = db.execute("SELECT config_json FROM workflow_templates WHERE id=?", (workflow_id,)).fetchone()
        left = db.execute("SELECT columns_json FROM datasets WHERE id=?", (left_id,)).fetchone()
        right = db.execute("SELECT columns_json FROM datasets WHERE id=?", (right_id,)).fetchone()
        if not workflow or not left or not right:
            raise HTTPException(404, "Workflow or dataset not found")
        config = json.loads(workflow["config_json"])
        left_columns, right_columns = json.loads(left["columns_json"]), json.loads(right["columns_json"])
        if not config.get("key_mappings") or any(m.get("left") not in left_columns or m.get("right") not in right_columns for m in config.get("key_mappings", [])):
            raise HTTPException(400, "The selected workflow fields do not match the chosen datasets")
        amount = config.get("amount_mapping")
        if amount and (amount.get("left") not in left_columns or amount.get("right") not in right_columns):
            raise HTTPException(400, "The selected workflow amount fields do not match the chosen datasets")
        date_window = config.get("date_window") or {}
        if date_window and (date_window.get("left") not in left_columns or date_window.get("right") not in right_columns):
            raise HTTPException(400, "The selected workflow date fields do not match the chosen datasets")
        next_run = next_automation_time(cadence) if schedule["enabled"] else schedule["next_run_at"]
        db.execute("UPDATE automation_schedules SET name=?,workflow_id=?,left_dataset_id=?,right_dataset_id=?,cadence=?,approval_required=?,next_run_at=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",
                   (name, workflow_id, left_id, right_id, cadence, approval_required, next_run, schedule_id))
        audit(db, user["id"], "update_automation_schedule", "automation_schedule", schedule_id,
              {"name": name, "workflow_id": workflow_id, "left_dataset_id": left_id, "right_dataset_id": right_id, "cadence": cadence, "approval_required": bool(approval_required)})
    return {"id": schedule_id, "name": name, "next_run_at": next_run}

@app.delete("/api/automation/schedules/{schedule_id}")
def delete_automation_schedule(schedule_id: int, user=Depends(require("analyst"))):
    with connect() as db:
        schedule = db.execute("SELECT owner_id,name FROM automation_schedules WHERE id=? AND archived=0", (schedule_id,)).fetchone()
        if not schedule:
            raise HTTPException(404, "Automation schedule not found")
        if schedule["owner_id"] != user["id"] and user["role"] != "admin":
            raise HTTPException(403, "Only the schedule owner or an administrator can delete it")
        db.execute("UPDATE automation_schedules SET enabled=0,archived=1,updated_at=CURRENT_TIMESTAMP WHERE id=?", (schedule_id,))
        audit(db, user["id"], "archive_automation_schedule", "automation_schedule", schedule_id, {"name": schedule["name"], "history_retained": True})
    return {"id": schedule_id, "archived": True}

@app.post("/api/automation/schedules/{schedule_id}/run")
def run_automation_now(schedule_id: int, user=Depends(require("analyst"))):
    with connect() as db:
        schedule = db.execute("SELECT owner_id FROM automation_schedules WHERE id=? AND archived=0", (schedule_id,)).fetchone()
    if not schedule:
        raise HTTPException(404, "Automation schedule not found")
    if schedule["owner_id"] != user["id"] and user["role"] != "admin":
        raise HTTPException(403, "Only the schedule owner or an administrator can run it")
    return run_automation_schedule(schedule_id, "manual", user["id"])

@app.patch("/api/automation/schedules/{schedule_id}/status")
def set_automation_status(schedule_id: int, payload: AutomationScheduleStatus, user=Depends(require("analyst"))):
    with connect() as db:
        schedule = db.execute("SELECT owner_id,cadence FROM automation_schedules WHERE id=? AND archived=0", (schedule_id,)).fetchone()
        if not schedule:
            raise HTTPException(404, "Automation schedule not found")
        if schedule["owner_id"] != user["id"] and user["role"] != "admin":
            raise HTTPException(403, "Only the schedule owner or an administrator can change it")
        next_run = next_automation_time(schedule["cadence"]) if payload.enabled else db.execute("SELECT next_run_at FROM automation_schedules WHERE id=?", (schedule_id,)).fetchone()["next_run_at"]
        db.execute("UPDATE automation_schedules SET enabled=?,next_run_at=?,updated_at=CURRENT_TIMESTAMP WHERE id=?", (int(payload.enabled), next_run, schedule_id))
        audit(db, user["id"], "resume_automation_schedule" if payload.enabled else "pause_automation_schedule", "automation_schedule", schedule_id)
    return {"id": schedule_id, "enabled": payload.enabled, "next_run_at": next_run}

@app.get("/api/automation/executions/{execution_id}/export.csv")
def download_automation_report(execution_id: int, user=Depends(current_user)):
    with connect() as db:
        row = db.execute("SELECT e.report_file,s.owner_id FROM automation_executions e LEFT JOIN automation_schedules s ON s.id=e.schedule_id WHERE e.id=?", (execution_id,)).fetchone()
    if not row or not row["report_file"]:
        raise HTTPException(404, "Automation report is not available")
    if row["owner_id"] != user["id"] and user["role"] != "admin":
        raise HTTPException(403, "Only the schedule owner or an administrator can download this report")
    if row["report_file"] != f"execution-{execution_id}.csv":
        raise HTTPException(404, "Automation report is not available")
    path = DATA_DIR / "automation_reports" / row["report_file"]
    if not path.is_file():
        raise HTTPException(404, "Automation report file is missing")
    return FileResponse(path, media_type="text/csv", filename=f"ido-automation-execution-{execution_id}.csv")

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

@app.get("/api/report-views")
def list_report_views(user=Depends(current_user)):
    with connect() as db:
        rows = db.execute("SELECT id,name,config_json,created_at,updated_at FROM report_views WHERE user_id=? ORDER BY name", (user["id"],)).fetchall()
    return [{**dict(row), "config": json.loads(row["config_json"])} for row in rows]

@app.post("/api/report-views")
def save_report_view(payload: ReportViewInput, user=Depends(require("analyst"))):
    allowed = {"dimension", "metric", "chart", "filters"}
    if not payload.name.strip():
        raise HTTPException(400, "Report view name cannot be blank")
    if set(payload.config) - allowed:
        raise HTTPException(400, "Report view contains unsupported settings")
    choices = {"dimension": {"date", "workflow", "approval_status"},
               "metric": {"runs", "matched", "exceptions", "match_rate", "confidence", "variance"},
               "chart": {"line", "bar"}}
    for field, values in choices.items():
        if field in payload.config and (not isinstance(payload.config[field], str) or payload.config[field] not in values):
            raise HTTPException(400, f"Unsupported report {field}")
    filters = payload.config.get("filters", {})
    if not isinstance(filters, dict) or set(filters) - {"date_from", "date_to", "workflow_id", "approval_status"}:
        raise HTTPException(400, "Report view contains unsupported filters")
    with connect() as db:
        db.execute("INSERT INTO report_views(user_id,name,config_json) VALUES(?,?,?) ON CONFLICT(user_id,name) DO UPDATE SET config_json=excluded.config_json,updated_at=CURRENT_TIMESTAMP",
                   (user["id"], payload.name.strip(), json.dumps(payload.config)))
        row = db.execute("SELECT id,name,config_json,created_at,updated_at FROM report_views WHERE user_id=? AND name=?", (user["id"], payload.name.strip())).fetchone()
        audit(db, user["id"], "save_report_view", "report_view", row["id"])
    return {**dict(row), "config": json.loads(row["config_json"])}

@app.delete("/api/report-views/{view_id}")
def delete_report_view(view_id: int, user=Depends(require("analyst"))):
    with connect() as db:
        cur = db.execute("DELETE FROM report_views WHERE id=? AND user_id=?", (view_id, user["id"]))
        if not cur.rowcount:
            raise HTTPException(404, "Saved report view not found")
        audit(db, user["id"], "delete_report_view", "report_view", view_id)
    return {"ok": True}

@app.get("/api/reports/export.csv")
def export_report(date_from: str | None = None, date_to: str | None = None,
                  workflow_id: int | None = Query(default=None, ge=1), approval_status: str | None = None,
                  user=Depends(current_user)):
    report = build_report(*validated_report_filters(date_from, date_to, workflow_id, approval_status))
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    fields = ["id", "name", "created_at", "workflow_name", "left_dataset", "right_dataset", "approval_status", "matched", "unmatched_left", "unmatched_right", "exceptions", "total_records", "match_rate", "average_score", "matched_left_amount", "matched_right_amount", "matched_variance", "unmatched_left_amount", "unmatched_right_amount"]
    write_csv_row(writer, fields)
    for run in report["runs"]:
        write_csv_row(writer, [run.get(field) for field in fields])
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
    write_csv_row(writer, ["run_id", "run_name", "created_at", "approval_status", "exception_type", "left_record", "right_record", "explanation"])
    if ids:
        with connect() as db:
            for offset in range(0, len(ids), 500):
                chunk = ids[offset:offset + 500]
                placeholders = ",".join("?" for _ in chunk)
                rows = db.execute(f"SELECT r.id,r.name,r.created_at,a.status approval_status,x.status exception_type,x.left_json,x.right_json,x.explanation FROM results x JOIN runs r ON r.id=x.run_id LEFT JOIN approvals a ON a.run_id=r.id WHERE x.run_id IN ({placeholders}) AND x.status!='matched' ORDER BY r.id DESC,x.id", chunk).fetchall()
                for row in rows:
                    write_csv_row(writer, [row["id"], row["name"], row["created_at"], row["approval_status"] or "not_requested", row["exception_type"], row["left_json"] or "", row["right_json"] or "", row["explanation"]])
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
    write_csv_row(writer, ["status", "score", "explanation", "left_record_json", "right_record_json"])
    for row in rows:
        write_csv_row(writer, [row["status"], row["score"], row["explanation"], row["left_json"] or "", row["right_json"] or ""])
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
    if payload.decision == "rejected" and not payload.comment.strip():
        raise HTTPException(400, "A comment explaining a rejection is required")
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

@app.get("/api/approvals")
def approval_history(user=Depends(current_user)):
    with connect() as db:
        rows = db.execute("""SELECT a.run_id,a.status,a.comment,a.requested_at,a.decided_at,
          req.username requested_by,dec.username decided_by,r.name run_name,r.created_by
          FROM approvals a JOIN runs r ON r.id=a.run_id JOIN users req ON req.id=a.requested_by
          LEFT JOIN users dec ON dec.id=a.decided_by ORDER BY COALESCE(a.decided_at,a.requested_at) DESC,a.run_id DESC LIMIT 200""").fetchall()
    return [dict(row) for row in rows]

@app.get("/api/audit")
def audit_events(user=Depends(require("approver"))):
    with connect() as db:
        return [dict(r) for r in db.execute("SELECT a.*,u.username FROM audit_log a LEFT JOIN users u ON u.id=a.actor_id ORDER BY a.id DESC LIMIT 200")]
