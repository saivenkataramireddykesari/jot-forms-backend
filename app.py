from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import pymysql
import base64 as b64lib
import jwt
import datetime
import os
from dotenv import load_dotenv
from contextlib import asynccontextmanager

load_dotenv()

# ─── JWT Config (no expiry) ───────────────────────────────────────────────────
JWT_SECRET = 'emp_portal_super_secret_2024'
JWT_ALGO   = 'HS256'

# ─── Database Configuration ───────────────────────────────────────────────────
db_config = {
    'host':         os.getenv('DB_HOST', 'localhost'),
    'port':         int(os.getenv('DB_PORT', 3306)),
    'user':         os.getenv('DB_USER', 'root'),
    'password':     os.getenv('DB_PASSWORD', ''),
    'database':     os.getenv('DB_NAME', 'employee_portal_db'),
    'cursorclass':  pymysql.cursors.DictCursor,
    'connect_timeout': 10,
    'charset':      'utf8mb4'
}

if os.getenv('DB_SSL_MODE') == 'REQUIRED':
    db_config['ssl'] = {'ssl': True}

# ─── DB Helpers ───────────────────────────────────────────────────────────────
def get_db_connection():
    try:
        return pymysql.connect(**db_config)
    except Exception as e:
        print(f"[DB ERROR] {e}")
        return None

def init_db():
    try:
        # Ensure DB exists
        temp_cfg = {k: v for k, v in db_config.items() if k != 'database'}
        if 'ssl' in db_config:
            temp_cfg['ssl'] = db_config['ssl']
        conn = pymysql.connect(**temp_cfg)
        with conn.cursor() as cur:
            db_name = os.getenv('DB_NAME', 'employee_portal_db')
            cur.execute(f"CREATE DATABASE IF NOT EXISTS {db_name}")
        conn.commit()
        conn.close()

        conn = get_db_connection()
        if not conn:
            return

        with conn.cursor() as cur:
            # ── admins ────────────────────────────────────────────────────────
            cur.execute("""
            CREATE TABLE IF NOT EXISTS admins (
                id       INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50)  NOT NULL UNIQUE,
                password VARCHAR(100) NOT NULL
            )""")
            cur.execute("SELECT COUNT(*) as cnt FROM admins")
            if cur.fetchone()['cnt'] == 0:
                cur.execute("INSERT INTO admins (username, password) VALUES (%s,%s)",
                            ('admin', 'admin123'))

            # ── forms ─────────────────────────────────────────────────────────
            cur.execute("""
            CREATE TABLE IF NOT EXISTS forms (
                id       INT AUTO_INCREMENT PRIMARY KEY,
                division VARCHAR(50)  NOT NULL,
                name     VARCHAR(100) NOT NULL,
                url      VARCHAR(500) NOT NULL
            )""")

            # ── auto_login_tokens (single source of truth for employees) ──────
            cur.execute("""
            CREATE TABLE IF NOT EXISTS auto_login_tokens (
                id          INT AUTO_INCREMENT PRIMARY KEY,
                employee_id VARCHAR(50)  NOT NULL,
                token       VARCHAR(255) NOT NULL UNIQUE,
                is_used     TINYINT(1)   DEFAULT 0,
                created_at  TIMESTAMP    DEFAULT CURRENT_TIMESTAMP,
                expires_at  DATETIME     NOT NULL,
                used_at     DATETIME,
                division    VARCHAR(50)  NOT NULL
            )""")

            # Seed default employees if table is empty
            cur.execute("SELECT COUNT(*) as cnt FROM auto_login_tokens")
            if cur.fetchone()['cnt'] == 0:
                seeds = [
                    ('EMP1001', 'tok_EMP1001_maxmus',   'maxmus'),
                    ('EMP1002', 'tok_EMP1002_nucles',   'nucles'),
                    ('EMP1003', 'tok_EMP1003_gladius',  'gladius'),
                    ('EMP1004', 'tok_EMP1004_stimulas', 'stimulas'),
                    ('EMP1005', 'tok_EMP1005_glamus',   'glamus'),
                    ('EMP1006', 'tok_EMP1006_nutrius',  'nutrius'),
                ]
                cur.executemany(
                    "INSERT INTO auto_login_tokens (employee_id, token, expires_at, division) VALUES (%s,%s,'2099-12-31 23:59:59',%s)",
                    seeds
                )

        conn.commit()
        conn.close()
        print("[INIT] Database ready.")
    except Exception as e:
        print(f"[INIT ERROR] {e}")

# ─── Pydantic Models ──────────────────────────────────────────────────────────
class AdminLoginRequest(BaseModel):
    username: str
    password: str

class FormRequest(BaseModel):
    division: str
    name: str
    url: str

class EmployeeLoginRequest(BaseModel):
    token: Optional[str] = None

# ─── JWT Helpers ──────────────────────────────────────────────────────────────
def generate_jwt(user_id: str, role: str = 'employee', division: str = None):
    payload = {
        'user_id':  user_id,
        'role':     role,
        'division': division,
        'iat': datetime.datetime.utcnow(),
        # No 'exp' → token never expires
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)

def verify_jwt(token_str: str):
    try:
        return jwt.decode(token_str, JWT_SECRET, algorithms=[JWT_ALGO],
                          options={"verify_exp": False})
    except Exception:
        return None

def get_current_admin(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authentication required")
    payload = verify_jwt(authorization[7:])
    if not payload or payload.get('role') != 'admin':
        raise HTTPException(status_code=403, detail="Admin access required")
    return payload

# ─── App Setup ────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Admin Routes ─────────────────────────────────────────────────────────────
@app.post("/api/admin/login")
def admin_login(req: AdminLoginRequest):
    conn = get_db_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection failed")
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM admins WHERE username=%s AND password=%s",
                        (req.username, req.password))
            admin = cur.fetchone()
        if not admin:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        return {
            "message":   "Login successful",
            "jwt_token": generate_jwt(admin['username'], role='admin'),
            "user":      {"username": admin['username'], "role": "admin"}
        }
    finally:
        conn.close()

@app.get("/api/admin/forms")
def get_all_forms(admin=Depends(get_current_admin)):
    conn = get_db_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection failed")
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM forms")
            return cur.fetchall()
    finally:
        conn.close()

@app.post("/api/admin/forms", status_code=201)
def add_form(req: FormRequest, admin=Depends(get_current_admin)):
    conn = get_db_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection failed")
    try:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO forms (division, name, url) VALUES (%s,%s,%s)",
                        (req.division, req.name, req.url))
        conn.commit()
        return {"message": "Form added successfully"}
    finally:
        conn.close()

@app.put("/api/admin/forms/{form_id}")
def update_form(form_id: int, req: FormRequest, admin=Depends(get_current_admin)):
    conn = get_db_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection failed")
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE forms SET division=%s, name=%s, url=%s WHERE id=%s",
                        (req.division, req.name, req.url, form_id))
        conn.commit()
        return {"message": "Form updated successfully"}
    finally:
        conn.close()

@app.delete("/api/admin/forms/{form_id}")
def delete_form(form_id: int, admin=Depends(get_current_admin)):
    conn = get_db_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection failed")
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM forms WHERE id=%s", (form_id,))
        conn.commit()
        return {"message": "Form deleted successfully"}
    finally:
        conn.close()

@app.get("/api/admin/tokens")
def get_all_tokens(admin=Depends(get_current_admin)):
    conn = get_db_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection failed")
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, employee_id, division, token FROM auto_login_tokens")
            tokens = cur.fetchall()
        for t in tokens:
            b64 = b64lib.b64encode(t['employee_id'].encode()).decode()
            t['portal_url']  = f"https://jotfrom.vercel.app/auth?data={b64}"
            t['data_param']  = b64
        return tokens
    finally:
        conn.close()

# ─── Employee Routes ──────────────────────────────────────────────────────────
@app.post("/api/employee/login")
def employee_login(req: EmployeeLoginRequest):
    """
    Accepts { "token": "<base64_of_employee_id>" }
    Decodes the Base64 → employee_id
    Looks up auto_login_tokens by employee_id
    Returns JWT + employee data
    """
    if not req.token:
        raise HTTPException(status_code=400, detail="token is required")

    conn = get_db_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection failed")
    try:
        with conn.cursor() as cur:
            # 1. Try searching by the raw token as EITHER the employee_id OR the token column
            cur.execute("SELECT * FROM auto_login_tokens WHERE employee_id=%s OR token=%s", (req.token, req.token))
            record = cur.fetchone()
            
            # 2. If not found, it might be a Base64 encoded ID (for ?data=RU1QMTAwMQ==)
            if not record:
                try:
                    # Pad correctly and decode
                    padded_token = req.token + "=" * (4 - len(req.token) % 4) if len(req.token) % 4 else req.token
                    decoded_id = b64lib.b64decode(padded_token).decode('utf-8').strip()
                    cur.execute("SELECT * FROM auto_login_tokens WHERE employee_id=%s", (decoded_id,))
                    record = cur.fetchone()
                except Exception:
                    pass

        if not record:
            raise HTTPException(status_code=401, detail="Invalid or expired token")

        # expires_at check (already set to 2099, just a safety guard)
        if record['expires_at'] < datetime.datetime.now():
            raise HTTPException(status_code=401, detail="Invalid or expired token")

        jwt_token = generate_jwt(record['employee_id'], role='employee',
                                 division=record['division'])
        return {
            "employee":  {"employee_id": record['employee_id'], "division": record['division']},
            "jwt_token": jwt_token
        }
    finally:
        conn.close()

@app.get("/api/employee/forms")
def get_employee_forms(division: str, authorization: Optional[str] = Header(None)):
    if authorization and authorization.startswith("Bearer "):
        payload = verify_jwt(authorization[7:])
        if not payload:
            raise HTTPException(status_code=401, detail="Session expired")
        if payload.get('division') != division:
            raise HTTPException(status_code=403, detail="Division mismatch")

    conn = get_db_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection failed")
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM forms WHERE division=%s", (division,))
            return cur.fetchall()
    finally:
        conn.close()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)
