from fastapi import FastAPI, Depends, HTTPException, Request, Header, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List
import pymysql
import traceback
import base64 as b64lib
import jwt
import datetime
import os
from dotenv import load_dotenv
from contextlib import asynccontextmanager

# Load environment variables from .env file
load_dotenv()

# ─── JWT Config ───────────────────────────────────────────────────────────────
JWT_SECRET  = 'emp_portal_super_secret_2024'
JWT_ALGO    = 'HS256'
JWT_EXPIRES = 8   # hours

# ─── Database Configuration ────────────────────────────────────────────────────
db_config = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'port': int(os.getenv('DB_PORT', 3306)),
    'user': os.getenv('DB_USER', 'root'),
    'password': os.getenv('DB_PASSWORD', ''),
    'database': os.getenv('DB_NAME', 'employee_portal_db'),
    'cursorclass': pymysql.cursors.DictCursor,
    'connect_timeout': 10,
    'charset': 'utf8mb4'
}

if os.getenv('DB_SSL_MODE') == 'REQUIRED':
    db_config['ssl'] = {'ssl': True}

# ─── DB Helper ─────────────────────────────────────────────────────────────────
def get_db_connection():
    try:
        conn = pymysql.connect(**db_config)
        return conn
    except Exception as e:
        print(f"[DB ERROR] {e}")
        return None

def init_db():
    try:
        temp_config = {k: v for k, v in db_config.items() if k != 'database'}
        if 'ssl' in db_config:
            temp_config['ssl'] = db_config['ssl']
        
        conn = pymysql.connect(**temp_config)
        with conn.cursor() as cursor:
            db_name = os.getenv('DB_NAME', 'employee_portal_db')
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS {db_name}")
        conn.commit()
        conn.close()

        conn = get_db_connection()
        if not conn: return

        with conn.cursor() as cursor:
            # Forms Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS forms (
                id       INT AUTO_INCREMENT PRIMARY KEY,
                division VARCHAR(50)  NOT NULL,
                name     VARCHAR(100) NOT NULL,
                url      VARCHAR(500) NOT NULL
            )""")

            # Tokens Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS tokens (
                id          INT AUTO_INCREMENT PRIMARY KEY,
                token       VARCHAR(100) NOT NULL UNIQUE,
                employee_id VARCHAR(50)  NOT NULL,
                division    VARCHAR(50)  NOT NULL
            )""")

            # Seed Tokens
            cursor.execute("SELECT COUNT(*) as count FROM tokens")
            if cursor.fetchone()['count'] == 0:
                sample_tokens = [
                    ('tok_EMP1001_maxmus',   'EMP1001', 'maxmus'),
                    ('tok_EMP1002_nucles',   'EMP1002', 'nucles'),
                    ('tok_EMP1003_gladius',  'EMP1003', 'gladius'),
                    ('tok_EMP1004_stimulas', 'EMP1004', 'stimulas'),
                    ('tok_EMP1005_glamus',   'EMP1005', 'glamus'),
                    ('tok_EMP1006_nutrius',  'EMP1006', 'nutrius'),
                ]
                cursor.executemany("INSERT INTO tokens (token, employee_id, division) VALUES (%s,%s,%s)", sample_tokens)

            # Admins Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS admins (
                id       INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50)  NOT NULL UNIQUE,
                password VARCHAR(100) NOT NULL
            )""")

            # Seed Admin
            cursor.execute("SELECT COUNT(*) as count FROM admins")
            if cursor.fetchone()['count'] == 0:
                cursor.execute("INSERT INTO admins (username, password) VALUES (%s, %s)", ('admin', 'admin123'))

        conn.commit()
        conn.close()
        print("[INIT] Database ready.")
    except Exception as e:
        print(f"[INIT ERROR] {e}")

# ─── Models ───────────────────────────────────────────────────────────────────
class AdminLoginRequest(BaseModel):
    username: str
    password: str

class FormRequest(BaseModel):
    division: str
    name: str
    url: str

class EmployeeLoginRequest(BaseModel):
    token: Optional[str] = None
    employee_id: Optional[str] = None

# ─── JWT helpers ───────────────────────────────────────────────────────────────
def generate_jwt(user_id: str, role: str = 'employee', division: str = None):
    payload = {
        'user_id':  user_id,
        'role':     role,
        'division': division,
        'iat': datetime.datetime.utcnow(),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)

def verify_jwt(token_str: str):
    try:
        payload = jwt.decode(token_str, JWT_SECRET, algorithms=[JWT_ALGO])
        return payload
    except Exception:
        return None

def get_current_admin(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authentication required")
    
    token = authorization[7:]
    payload = verify_jwt(token)
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

# ─── Routes ───────────────────────────────────────────────────────────────────

@app.post("/api/admin/login")
def admin_login(req: AdminLoginRequest):
    conn = get_db_connection()
    if not conn: raise HTTPException(status_code=500, detail="Database connection failed")
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM admins WHERE username=%s AND password=%s", (req.username, req.password))
            admin = cursor.fetchone()
        
        if not admin:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        token = generate_jwt(admin['username'], role='admin')
        return {
            "message": "Login successful",
            "jwt_token": token,
            "user": {"username": admin['username'], "role": "admin"}
        }
    finally:
        conn.close()

@app.get("/api/admin/forms")
def get_all_forms(admin=Depends(get_current_admin)):
    conn = get_db_connection()
    if not conn: raise HTTPException(status_code=500, detail="Database connection failed")
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM forms")
            return cursor.fetchall()
    finally:
        conn.close()

@app.post("/api/admin/forms", status_code=201)
def add_form(req: FormRequest, admin=Depends(get_current_admin)):
    conn = get_db_connection()
    if not conn: raise HTTPException(status_code=500, detail="Database connection failed")
    try:
        with conn.cursor() as cursor:
            cursor.execute("INSERT INTO forms (division, name, url) VALUES (%s,%s,%s)", (req.division, req.name, req.url))
        conn.commit()
        return {"message": "Form added successfully"}
    finally:
        conn.close()

@app.put("/api/admin/forms/{form_id}")
def update_form(form_id: int, req: FormRequest, admin=Depends(get_current_admin)):
    conn = get_db_connection()
    if not conn: raise HTTPException(status_code=500, detail="Database connection failed")
    try:
        with conn.cursor() as cursor:
            cursor.execute("UPDATE forms SET division=%s, name=%s, url=%s WHERE id=%s", (req.division, req.name, req.url, form_id))
        conn.commit()
        return {"message": "Form updated successfully"}
    finally:
        conn.close()

@app.delete("/api/admin/forms/{form_id}")
def delete_form(form_id: int, admin=Depends(get_current_admin)):
    conn = get_db_connection()
    if not conn: raise HTTPException(status_code=500, detail="Database connection failed")
    try:
        with conn.cursor() as cursor:
            cursor.execute("DELETE FROM forms WHERE id=%s", (form_id,))
        conn.commit()
        return {"message": "Form deleted successfully"}
    finally:
        conn.close()

@app.get("/api/admin/tokens")
def get_all_tokens(admin=Depends(get_current_admin)):
    conn = get_db_connection()
    if not conn: raise HTTPException(status_code=500, detail="Database connection failed")
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, employee_id, division FROM tokens")
            tokens = cursor.fetchall()
        for t in tokens:
            encoded = b64lib.b64encode(t['employee_id'].encode()).decode()
            t['portal_url'] = f"http://localhost:5173/auth?data={encoded}"
            t['data_param'] = encoded
        return tokens
    finally:
        conn.close()

@app.post("/api/employee/login")
def employee_login(req: EmployeeLoginRequest):
    employee_id = None
    if req.token:
        try:
            employee_id = b64lib.b64decode(req.token).decode('utf-8').strip()
        except:
            raise HTTPException(status_code=400, detail="Invalid token format")
    elif req.employee_id:
        employee_id = req.employee_id
    
    if not employee_id:
        raise HTTPException(status_code=400, detail="token or employee_id is required")

    conn = get_db_connection()
    if not conn: raise HTTPException(status_code=500, detail="Database connection failed")
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM tokens WHERE employee_id=%s", (employee_id,))
            emp = cursor.fetchone()
        
        if not emp:
            raise HTTPException(status_code=401, detail="Employee not found")
        
        token = generate_jwt(emp['employee_id'], role='employee', division=emp['division'])
        return {
            "message": "Login successful",
            "jwt_token": token,
            "employee": {"employee_id": emp['employee_id'], "division": emp['division']}
        }
    finally:
        conn.close()

@app.get("/api/employee/forms")
def get_employee_forms(division: str, authorization: Optional[str] = Header(None)):
    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:]
        payload = verify_jwt(token)
        if not payload:
            raise HTTPException(status_code=401, detail="Session expired")
        if payload.get('division') != division:
            raise HTTPException(status_code=403, detail="Division mismatch")

    conn = get_db_connection()
    if not conn: raise HTTPException(status_code=500, detail="Database connection failed")
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM forms WHERE division=%s", (division,))
            return cursor.fetchall()
    finally:
        conn.close()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)
