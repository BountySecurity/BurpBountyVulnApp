"""SQLi vulnerability endpoints - triggers 7 SQLi profiles."""
import sqlite3
import time
import re
from flask import Blueprint, request, make_response, current_app

sqli_bp = Blueprint('sqli', __name__, url_prefix='/sqli')


def get_db():
    conn = sqlite3.connect(current_app.config['DB_PATH'])
    conn.row_factory = sqlite3.Row
    return conn


@sqli_bp.route('/search')
def search():
    """Error-based SQLi. Triggers: SQLi (error messages)
    Simulates MySQL/Oracle/MSSQL error output when SQL injection chars are detected."""
    q = request.args.get('q', '')

    # Detect SQL injection characters/patterns
    sqli_chars = ["'", '"', '`', '\\', ';', '--', '/*', '*/', 'UNION', 'SELECT',
                  'OR ', 'AND ', 'SLEEP', 'WAITFOR', 'BENCHMARK']
    is_sqli = any(c in q or c in q.upper() for c in sqli_chars)

    if is_sqli:
        return f"""<html><body>
<h1>Database Error</h1>
<p>Warning: mysql_fetch_array(): supplied argument is not a valid MySQL result resource</p>
<p>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '{q}' at line 1</p>
<p>ORA-00933: SQL command not properly ended</p>
<p>Microsoft OLE DB Provider for SQL Server error '80040e14'</p>
<p>Unclosed quotation mark after the character string '{q}'</p>
<p>pg_query(): Query failed: ERROR: unterminated quoted string at or near "'{q}"</p>
</body></html>""", 500

    db = get_db()
    try:
        cursor = db.execute("SELECT * FROM products WHERE name LIKE ? OR category LIKE ?",
                            (f'%{q}%', f'%{q}%'))
        rows = cursor.fetchall()
        results = ''.join(f'<tr><td>{r["id"]}</td><td>{r["name"]}</td><td>{r["price"]}</td></tr>' for r in rows)
        return f"""<html><body>
<h1>Product Search</h1>
<form><input name="q" value="{q}"><button>Search</button></form>
<table><tr><th>ID</th><th>Name</th><th>Price</th></tr>{results}</table>
</body></html>"""
    except Exception as e:
        return f"""<html><body>
<h1>Database Error</h1>
<p>You have an error in your SQL syntax; {e}</p>
</body></html>""", 500


@sqli_bp.route('/user')
def user_by_id():
    """SQLi by ID parameter. Triggers: SQLi, SQLi_StatusCode, SQLi_ContentLength"""
    uid = request.args.get('id', '1')

    # Detect SQL injection
    sqli_chars = ["'", '"', '`', '\\', ';', '--', '/*']
    is_sqli = any(c in uid for c in sqli_chars)

    if is_sqli:
        return f"""<html><body>
<h1>Error</h1>
<p>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '{uid}'</p>
<p>Warning: mysql_fetch_array(): supplied argument is not a valid MySQL result resource</p>
</body></html>""", 500

    db = get_db()
    try:
        cursor = db.execute(f"SELECT * FROM users WHERE id = {uid}")
        rows = cursor.fetchall()
        if rows:
            r = rows[0]
            padding = "<!-- user data padding -->\n" * 200
            return f"""<html><body>
<h1>User Profile</h1>
<p>ID: {r['id']}</p><p>Username: {r['username']}</p><p>Email: {r['email']}</p><p>Role: {r['role']}</p>
<a href="/sqli/user?id=1">User 1</a> <a href="/sqli/user?id=2">User 2</a> <a href="/sqli/user?id=3">User 3</a>
{padding}
</body></html>"""
        return "<html><body><h1>User not found</h1></body></html>", 404
    except Exception as e:
        return f"""<html><body>
<h1>Error</h1>
<p>You have an error in your SQL syntax; {e}</p>
</body></html>""", 500


@sqli_bp.route('/login', methods=['GET', 'POST'])
def login():
    """SQLi in login form. Triggers: SQLi"""
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        db = get_db()
        try:
            cursor = db.execute(f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'")
            user = cursor.fetchone()
            if user:
                return f"<html><body><h1>Welcome {user['username']}!</h1></body></html>"
            return "<html><body><h1>Invalid credentials</h1></body></html>"
        except Exception as e:
            return f"""<html><body><h1>SQL Error</h1>
<p>You have an error in your SQL syntax; {e}</p>
<p>Warning: mysql_fetch_array(): supplied argument is not valid</p>
</body></html>""", 500
    return """<html><body>
<h1>Login</h1>
<form method="POST">
<input name="username" placeholder="Username"><br>
<input name="password" type="password" placeholder="Password"><br>
<button>Login</button>
</form></body></html>"""


@sqli_bp.route('/time')
def time_based():
    """Time-based SQLi. Triggers: SQLi_Timebased, SQLi_Timebased_Encoded_*
    Detects sleep/waitfor/benchmark patterns and actually delays."""
    uid = request.args.get('id', '1')

    # Check for time-based SQLi patterns and actually sleep
    lower = uid.lower()
    sleep_match = re.search(r'sleep\s*\(\s*(\d+)\s*\)', lower)
    waitfor_match = re.search(r"waitfor\s+delay\s+'(\d+):(\d+):(\d+)'", lower)
    pg_match = re.search(r'pg_sleep\s*\(\s*(\d+)\s*\)', lower)
    benchmark_match = re.search(r'benchmark\s*\(\s*(\d+)', lower)

    delay = 0
    if sleep_match:
        delay = min(int(sleep_match.group(1)), 30)
    elif waitfor_match:
        delay = min(int(waitfor_match.group(2)) * 60 + int(waitfor_match.group(3)), 30)
    elif pg_match:
        delay = min(int(pg_match.group(1)), 30)
    elif benchmark_match:
        # Simulate benchmark delay
        count = int(benchmark_match.group(1))
        delay = min(count // 5000000, 30)

    if delay > 0:
        time.sleep(delay)

    db = get_db()
    try:
        cursor = db.execute(f"SELECT * FROM users WHERE id = {uid.split(';')[0].split('--')[0].strip()}")
        rows = cursor.fetchall()
        if rows:
            r = rows[0]
            return f"<html><body><h1>User: {r['username']}</h1></body></html>"
        return "<html><body><h1>User not found</h1></body></html>"
    except:
        return "<html><body><h1>Error</h1></body></html>", 500


@sqli_bp.route('/status')
def status_code():
    """Status-code based SQLi. Triggers: SQLi_StatusCode
    Returns 500 on SQL error (caused by single quote)."""
    uid = request.args.get('id', '1')
    db = get_db()
    try:
        cursor = db.execute(f"SELECT * FROM users WHERE id = {uid}")
        rows = cursor.fetchall()
        return f"<html><body><h1>Found {len(rows)} users</h1></body></html>"
    except:
        return "<html><body><h1>Internal Server Error</h1></body></html>", 500


@sqli_bp.route('/length')
def content_length():
    """Content-length differential SQLi. Triggers: SQLi_ContentLength
    Returns very different response sizes on error vs success."""
    q = request.args.get('q', '')
    db = get_db()
    try:
        cursor = db.execute(f"SELECT * FROM users WHERE username LIKE '%{q}%'")
        rows = cursor.fetchall()
        # Generate a large response on success
        result_parts = []
        for r in rows:
            result_parts.append(f"""
            <div class="user-card">
                <h2>{r['username']}</h2>
                <p>Email: {r['email']}</p>
                <p>Role: {r['role']}</p>
                <p>ID: {r['id']}</p>
                <p>Status: Active</p>
                <p>Created: 2024-01-01</p>
                <p>Last Login: 2024-06-15</p>
                <p>Department: Engineering</p>
                <p>Location: Remote</p>
            </div>""")
        padding = "<!-- padding content -->\n" * 200
        return f"""<html><body><h1>User Search</h1>{''.join(result_parts)}{padding}</body></html>"""
    except:
        # Very short response on error -> big content length difference
        return "<html><body><h1>Error</h1></body></html>", 200


@sqli_bp.route('/oob')
def oob_sqli():
    """OOB SQLi endpoint. Triggers: SQLi_Collaborator
    Simulates a database that would process LOAD_FILE, UTL_HTTP, etc."""
    uid = request.args.get('id', '1')
    db = get_db()
    try:
        cursor = db.execute(f"SELECT * FROM users WHERE id = {uid.split(';')[0].split('--')[0].strip()}")
        rows = cursor.fetchall()
        if rows:
            r = rows[0]
            return f"<html><body><h1>User: {r['username']}</h1></body></html>"
        return "<html><body><h1>Not found</h1></body></html>"
    except:
        return "<html><body><h1>Error</h1></body></html>", 500
