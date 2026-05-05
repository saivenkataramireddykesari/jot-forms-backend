from fastapi import FastAPI, Depends, HTTPException, Header, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import pymysql
import base64 as b64lib
import jwt
import datetime
import os
import logging
from dotenv import load_dotenv
from contextlib import asynccontextmanager

load_dotenv()

# ─── Logging Configuration ──────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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

def get_forms_db_connection():
    """
    Connect to the forms database.
    - Locally: uses FORMS_DB_* env vars (pointing to Aiven)
    - On Render/Production: falls back to main DB config (DB_* vars already point to Aiven)
    """
    forms_host = os.getenv('FORMS_DB_HOST')
    if not forms_host:
        # Fallback: use main db_config (works on Render where DB_* = Aiven)
        return get_db_connection()
    try:
        cfg = {
            'host':         forms_host,
            'port':         int(os.getenv('FORMS_DB_PORT', 3306)),
            'user':         os.getenv('FORMS_DB_USER'),
            'password':     os.getenv('FORMS_DB_PASSWORD'),
            'database':     os.getenv('FORMS_DB_NAME'),
            'cursorclass':  pymysql.cursors.DictCursor,
            'connect_timeout': 10,
            'charset':      'utf8mb4'
        }
        if os.getenv('FORMS_DB_SSL') == 'REQUIRED':
            cfg['ssl'] = {'ssl': True}
        return pymysql.connect(**cfg)
    except Exception as e:
        print(f"[FORMS DB ERROR] {e}")
        return None

def init_db():
    try:
        # Step 1: Try to ensure the database exists (may fail due to privileges)
        try:
            temp_cfg = {k: v for k, v in db_config.items() if k != 'database'}
            if 'ssl' in db_config:
                temp_cfg['ssl'] = db_config['ssl']
            conn = pymysql.connect(**temp_cfg)
            with conn.cursor() as cur:
                db_name = os.getenv('DB_NAME', 'employee_portal_db')
                cur.execute(f"CREATE DATABASE IF NOT EXISTS {db_name}")
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[INIT INFO] Database creation skipped or failed: {e}")

        # Step 2: Connect to the specific database and create tables
        conn = get_db_connection()
        if not conn:
            print("[INIT ERROR] Could not connect to database to create tables.")
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
            try:
                cur.execute("SELECT * FROM admins WHERE username=%s AND password=%s",
                            (req.username, req.password))
                admin = cur.fetchone()
                if admin:
                    return {
                        "message":   "Login successful",
                        "jwt_token": generate_jwt(admin['username'], role='admin'),
                        "user":      {"username": admin['username'], "role": "admin"}
                    }
            except Exception as e:
                logger.warning(f"[ADMIN] Table check failed: {e}")
                # Fallback to hardcoded admin if table missing
                if req.username == 'admin' and req.password == 'admin123':
                    return {
                        "message":   "Login successful (fallback)",
                        "jwt_token": generate_jwt('admin', role='admin'),
                        "user":      {"username": 'admin', "role": "admin"}
                    }
        
        raise HTTPException(status_code=401, detail="Invalid credentials")
    finally:
        conn.close()

@app.get("/api/admin/forms")
def get_all_forms(admin=Depends(get_current_admin)):
    conn = get_forms_db_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Forms database connection failed")
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM forms")
            return cur.fetchall()
    finally:
        conn.close()

@app.post("/api/admin/forms", status_code=201)
def add_form(req: FormRequest, admin=Depends(get_current_admin)):
    conn = get_forms_db_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Forms database connection failed")
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
    conn = get_forms_db_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Forms database connection failed")
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
    conn = get_forms_db_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Forms database connection failed")
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

@app.get("/auth")
def auth_endpoint(data: str = Query(..., description="Base64 encoded employee_id")):
    """
    Auto-login endpoint that validates token from URL query parameter.
    
    URL format: /auth?data=RU1QMTAwNg==
    
    Returns:
        - 200: {"employee_id": "...", "division": "..."}
        - 401: Invalid, expired, or already used token
    """
    logger.info(f"[AUTH] Received data parameter: {data}")
    
    if not data or not data.strip():
        logger.warning("[AUTH] Empty data parameter")
        raise HTTPException(status_code=401, detail="Invalid token: data parameter is required")
    
    # Decode Base64 to get employee_id
    try:
        clean_b64 = data.strip()
        # Normalize padding for Base64
        raw_b64 = clean_b64.rstrip('=')
        padded = raw_b64 + "=" * ((4 - len(raw_b64) % 4) % 4)
        employee_id = b64lib.b64decode(padded).decode('utf-8').strip()
        logger.info(f"[AUTH] Decoded employee_id: {employee_id}")
    except Exception as e:
        logger.error(f"[AUTH] Base64 decode failed: {e}, data={data}")
        raise HTTPException(status_code=401, detail="Invalid token: malformed data")
    
    # Database lookup with proper filters
    conn = get_db_connection()
    if not conn:
        logger.error("[AUTH] Database connection failed")
        raise HTTPException(status_code=500, detail="Database connection failed")
    
    try:
        with conn.cursor() as cur:
            # CRITICAL: Use exact match on employee_id, filter unused & non-expired tokens
            # Use %s placeholders (PyMySQL style), NOT ?
            # Use fetchone() to get single row, NOT fetchall()
            sql = """
                SELECT employee_id, division, is_used, expires_at
                FROM auto_login_tokens
                WHERE employee_id = %s
                  AND is_used = 0
                  AND expires_at > NOW()
                LIMIT 1
            """
            logger.info(f"[AUTH] Executing SQL: {sql.strip()} with param: {employee_id}")
            cur.execute(sql, (employee_id,))
            record = cur.fetchone()
            
            logger.info(f"[AUTH] DB Result: {record}")
            
            if not record:
                logger.warning(f"[AUTH] No valid token found for employee_id: {employee_id}")
                raise HTTPException(status_code=401, detail="Invalid or expired token")
            
            # Double-check the values (defensive programming)
            if record.get('is_used'):
                logger.warning(f"[AUTH] Token already used for: {employee_id}")
                raise HTTPException(status_code=401, detail="Token already used")
            
            expires_at = record.get('expires_at')
            if expires_at and expires_at < datetime.datetime.now():
                logger.warning(f"[AUTH] Token expired for: {employee_id}, expires_at={expires_at}")
                raise HTTPException(status_code=401, detail="Token expired")
            
            result = {
                "employee_id": record['employee_id'],
                "division": record['division']
            }
            logger.info(f"[AUTH] Success: {result}")
            return result
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[AUTH] Database error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        conn.close()


@app.post("/api/employee/login")
def employee_login(req: EmployeeLoginRequest):
    """
    Legacy login endpoint - kept for backward compatibility.
    Uses token-based lookup with is_used and expires_at checks.
    """
    if not req.token:
        raise HTTPException(status_code=400, detail="token is required")

    conn = get_db_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection failed")
    try:
        clean_token = req.token.strip()
        logger.info(f"[LEGACY LOGIN] Token: {clean_token}")
        
        with conn.cursor() as cur:
            # 1. Try auto_login_tokens if it exists
            record = None
            try:
                cur.execute(
                    """
                    SELECT * FROM auto_login_tokens
                    WHERE (token = %s OR employee_id = %s)
                      AND is_used = 0
                      AND expires_at > NOW()
                    LIMIT 1
                    """,
                    (clean_token, clean_token)
                )
                record = cur.fetchone()
            except Exception as e:
                logger.info(f"[LOGIN] auto_login_tokens check skipped: {e}")

            # 2. Handle Decoded ID or Plain Text
            decoded_id = None
            try:
                raw_b64 = clean_token.rstrip('=')
                if len(raw_b64) % 4 != 1:  # Only attempt if length is valid for B64
                    padded = raw_b64 + "=" * ((4 - len(raw_b64) % 4) % 4)
                    decoded_id = b64lib.b64decode(padded).decode('utf-8').strip()
                    logger.info(f"[LOGIN] Decoded ID: {decoded_id}")
            except Exception as e:
                logger.info(f"[LOGIN] Base64 decode skipped/failed: {e}")

            # 3. Final Fallback: Check auto_login_tokens or organogram
            if not record:
                # Try auto_login_tokens with decoded ID
                if decoded_id:
                    try:
                        cur.execute(
                            "SELECT * FROM auto_login_tokens WHERE employee_id = %s AND is_used = 0 AND expires_at > NOW() LIMIT 1",
                            (decoded_id,)
                        )
                        record = cur.fetchone()
                    except: pass
                
                # Check 'organogram' table (User's specific structure)
                if not record:
                    # Check both the raw input and the decoded ID (if any)
                    search_ids = [clean_token]
                    if decoded_id: search_ids.append(decoded_id)
                    
                    logger.info(f"[LOGIN] Checking 'organogram' table for {search_ids}")
                    cur.execute(
                        "SELECT Emp_Code as employee_id, Division as division FROM organogram WHERE Emp_Code IN %s LIMIT 1",
                        (tuple(search_ids),)
                    )
                    record = cur.fetchone()
                    if record:
                        logger.info(f"[LOGIN] Found in 'organogram' table: {record}")

        if not record:
            raise HTTPException(status_code=401, detail="Employee ID not found in database")

        # Normalize division for frontend (ensure lowercase if needed, or keep as is)
        div = record['division'].lower().strip() if record['division'] else 'unknown'
        
        # Create session JWT
        jwt_token = generate_jwt(record['employee_id'], role='employee',
                                 division=div)
        return {
            "employee":  {"employee_id": record['employee_id'], "division": div},
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

    conn = get_forms_db_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Forms database connection failed")
    try:
        with conn.cursor() as cur:
            # Use case-insensitive matching for division
            cur.execute("SELECT * FROM forms WHERE LOWER(division) = LOWER(%s)", (division,))
            return cur.fetchall()
    finally:
        conn.close()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)
