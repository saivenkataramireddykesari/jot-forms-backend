from flask import Flask, request, jsonify
from flask_cors import CORS
import pymysql
import traceback
import base64 as b64lib
import jwt
import datetime
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
CORS(app)

# ─── JWT Secret (change this to a strong random string in production) ──────────
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

# If SSL is required (e.g., for Aiven)
if os.getenv('DB_SSL_MODE') == 'REQUIRED':
    db_config['ssl'] = {'ssl': True}

# ─── DB Helper ─────────────────────────────────────────────────────────────────
def get_db_connection():
    try:
        print("[DB] Connecting to MySQL...")
        conn = pymysql.connect(**db_config)
        print("[DB] Connection successful.")
        return conn
    except pymysql.err.OperationalError as e:
        print(f"[DB ERROR] OperationalError: {e}")
        return None
    except Exception as e:
        print(f"[DB ERROR] Unexpected: {e}")
        return None

# ─── Init DB ───────────────────────────────────────────────────────────────────
def init_db():
    try:
        temp_config = {k: v for k, v in db_config.items() if k != 'database'}
        if 'ssl' in db_config:
            temp_config['ssl'] = db_config['ssl']
        print("[INIT] Creating database if not exists...")
        conn = pymysql.connect(**temp_config)
        with conn.cursor() as cursor:
            db_name = os.getenv('DB_NAME', 'employee_portal_db')
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS {db_name}")
        conn.commit()
        conn.close()

        conn = get_db_connection()
        if not conn:
            print("[INIT ERROR] Cannot connect to DB for table setup.")
            return

        with conn.cursor() as cursor:
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS forms (
                id       INT AUTO_INCREMENT PRIMARY KEY,
                division VARCHAR(50)  NOT NULL,
                name     VARCHAR(100) NOT NULL,
                url      VARCHAR(500) NOT NULL
            )""")

            cursor.execute("""
            CREATE TABLE IF NOT EXISTS tokens (
                id          INT AUTO_INCREMENT PRIMARY KEY,
                token       VARCHAR(100) NOT NULL UNIQUE,
                employee_id VARCHAR(50)  NOT NULL,
                division    VARCHAR(50)  NOT NULL
            )""")

            cursor.execute("SELECT COUNT(*) as count FROM tokens")
            if cursor.fetchone()['count'] == 0:
                print("[INIT] Seeding default tokens...")
                sample_tokens = [
                    ('tok_EMP1001_maxmus',   'EMP1001', 'maxmus'),
                    ('tok_EMP1002_nucles',   'EMP1002', 'nucles'),
                    ('tok_EMP1003_gladius',  'EMP1003', 'gladius'),
                    ('tok_EMP1004_stimulas', 'EMP1004', 'stimulas'),
                    ('tok_EMP1005_glamus',   'EMP1005', 'glamus'),
                    ('tok_EMP1006_nutrius',  'EMP1006', 'nutrius'),
                ]
                cursor.executemany(
                    "INSERT INTO tokens (token, employee_id, division) VALUES (%s,%s,%s)",
                    sample_tokens
                )
        conn.commit()
        conn.close()
        print("[INIT] Database ready.")
    except Exception as e:
        print(f"[INIT ERROR] {e}")
        traceback.print_exc()

# ─── Safe JSON parser ──────────────────────────────────────────────────────────
def get_json_body():
    try:
        data = request.get_json(silent=True, force=True)
        if data is None:
            print("[REQUEST] Warning: body is None or not valid JSON.")
            return {}
        print(f"[REQUEST] Body: {data}")
        return data
    except Exception as e:
        print(f"[REQUEST ERROR] {e}")
        return {}

# ─── JWT helpers ───────────────────────────────────────────────────────────────
def generate_jwt(employee_id, division):
    """Create a signed JWT valid for JWT_EXPIRES hours."""
    payload = {
        'employee_id': employee_id,
        'division':    division,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=JWT_EXPIRES),
        'iat': datetime.datetime.utcnow(),
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)
    return token

def verify_jwt(token_str):
    """Decode and verify a JWT. Returns payload dict or None on failure."""
    try:
        payload = jwt.decode(token_str, JWT_SECRET, algorithms=[JWT_ALGO])
        return payload
    except jwt.ExpiredSignatureError:
        print("[JWT] Token expired.")
        return None
    except jwt.InvalidTokenError as e:
        print(f"[JWT] Invalid token: {e}")
        return None

def get_jwt_from_header():
    """Extract Bearer token from Authorization header."""
    auth = request.headers.get('Authorization', '')
    if auth.startswith('Bearer '):
        return auth[7:]
    return None

# ─── Admin: GET all forms ──────────────────────────────────────────────────────
@app.route('/api/admin/forms', methods=['GET'])
def get_all_forms():
    print("[ROUTE] GET /api/admin/forms")
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM forms")
            forms = cursor.fetchall()
        return jsonify(forms), 200
    except Exception as e:
        print(f"[ERROR] get_all_forms: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

# ─── Admin: POST add form ──────────────────────────────────────────────────────
@app.route('/api/admin/forms', methods=['POST'])
def add_form():
    print("[ROUTE] POST /api/admin/forms")
    data     = get_json_body()
    division = data.get('division', '').strip()
    name     = data.get('name',     '').strip()
    url      = data.get('url',      '').strip()

    if not division or not name or not url:
        return jsonify({'error': 'Missing required fields: division, name, url'}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "INSERT INTO forms (division, name, url) VALUES (%s,%s,%s)",
                (division, name, url)
            )
        conn.commit()
        return jsonify({'message': 'Form added successfully'}), 201
    except Exception as e:
        print(f"[ERROR] add_form: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

# ─── Admin: PUT update form ────────────────────────────────────────────────────
@app.route('/api/admin/forms/<int:form_id>', methods=['PUT'])
def update_form(form_id):
    print(f"[ROUTE] PUT /api/admin/forms/{form_id}")
    data     = get_json_body()
    division = data.get('division', '').strip()
    name     = data.get('name',     '').strip()
    url      = data.get('url',      '').strip()

    if not division or not name or not url:
        return jsonify({'error': 'Missing required fields: division, name, url'}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "UPDATE forms SET division=%s, name=%s, url=%s WHERE id=%s",
                (division, name, url, form_id)
            )
        conn.commit()
        return jsonify({'message': 'Form updated successfully'}), 200
    except Exception as e:
        print(f"[ERROR] update_form: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

# ─── Admin: DELETE form ────────────────────────────────────────────────────────
@app.route('/api/admin/forms/<int:form_id>', methods=['DELETE'])
def delete_form(form_id):
    print(f"[ROUTE] DELETE /api/admin/forms/{form_id}")
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    try:
        with conn.cursor() as cursor:
            cursor.execute("DELETE FROM forms WHERE id=%s", (form_id,))
        conn.commit()
        return jsonify({'message': 'Form deleted successfully'}), 200
    except Exception as e:
        print(f"[ERROR] delete_form: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

# ─── Admin: GET all tokens (read-only, for Employee URLs tab) ──────────────────
@app.route('/api/admin/tokens', methods=['GET'])
def get_all_tokens():
    print("[ROUTE] GET /api/admin/tokens")
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, employee_id, division FROM tokens")
            tokens = cursor.fetchall()
        for t in tokens:
            encoded = b64lib.b64encode(t['employee_id'].encode()).decode()
            t['portal_url'] = f"http://localhost:5173/auth?data={encoded}"
            t['data_param'] = encoded
        return jsonify(tokens), 200
    except Exception as e:
        print(f"[ERROR] get_all_tokens: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

# ─── Employee: Login with Base64 token → returns JWT ──────────────────────────
@app.route('/api/employee/login', methods=['POST'])
def employee_login():
    """
    Accepts:  { "token": "<base64_encoded_employee_id>" }
              OR { "employee_id": "<plain_employee_id>" }  (legacy)

    Flow:
      1. If 'token' key → base64 decode to get employee_id
      2. Look up employee_id in tokens table
      3. On success → generate JWT and return it
      4. On failure → 401
    """
    print("[ROUTE] POST /api/employee/login")
    data = get_json_body()

    b64_token   = data.get('token',       '').strip()
    plain_empid = data.get('employee_id', '').strip()

    employee_id = None

    # ── Decode Base64 token (primary path) ────────────────────────────────
    if b64_token:
        try:
            employee_id = b64lib.b64decode(b64_token).decode('utf-8').strip()
            print(f"[AUTH] Base64 decoded employee_id: {employee_id!r}")
        except Exception as e:
            print(f"[AUTH] Base64 decode failed: {e}")
            return jsonify({'error': 'Invalid token format. Base64 decode failed.'}), 400

    # ── Plain employee_id fallback ─────────────────────────────────────────
    elif plain_empid:
        employee_id = plain_empid
        print(f"[AUTH] Plain employee_id: {employee_id!r}")

    else:
        return jsonify({'error': 'token or employee_id is required'}), 400

    if not employee_id:
        return jsonify({'error': 'Token decodes to empty value'}), 400

    # ── DB lookup ─────────────────────────────────────────────────────────
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    try:
        with conn.cursor() as cursor:
            print(f"[SQL] SELECT * FROM tokens WHERE employee_id={employee_id!r}")
            cursor.execute("SELECT * FROM tokens WHERE employee_id=%s", (employee_id,))
            emp = cursor.fetchone()

        if not emp:
            print(f"[AUTH] No employee found for id: {employee_id!r}")
            return jsonify({'error': 'Invalid or expired token. Employee not found.'}), 401

        # ── Generate JWT ──────────────────────────────────────────────────
        jwt_token = generate_jwt(emp['employee_id'], emp['division'])
        print(f"[AUTH] JWT issued for {emp['employee_id']} / {emp['division']}")

        return jsonify({
            'message': 'Login successful',
            'jwt_token': jwt_token,
            'employee': {
                'employee_id': emp['employee_id'],
                'division':    emp['division']
            }
        }), 200

    except Exception as e:
        print(f"[ERROR] employee_login: {e}")
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

# ─── Employee: Get forms (JWT protected) ──────────────────────────────────────
@app.route('/api/employee/forms', methods=['GET'])
def get_employee_forms():
    division = request.args.get('division', '').strip()
    print(f"[ROUTE] GET /api/employee/forms?division={division!r}")

    # ── Verify JWT from Authorization header ──────────────────────────────
    token_str = get_jwt_from_header()
    if token_str:
        payload = verify_jwt(token_str)
        if not payload:
            return jsonify({'error': 'Session expired. Please re-open your portal link.'}), 401
        # Enforce: JWT division must match requested division
        if payload.get('division') != division:
            print(f"[SECURITY] Division mismatch: JWT={payload.get('division')!r} requested={division!r}")
            return jsonify({'error': 'Access denied. Division mismatch.'}), 403

    if not division:
        return jsonify({'error': 'Division query param is required'}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM forms WHERE division=%s", (division,))
            forms = cursor.fetchall()
            print(f"[SQL] {len(forms)} forms for '{division}'.")
        return jsonify(forms), 200
    except Exception as e:
        print(f"[ERROR] get_employee_forms: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

# ─── Run ───────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)
