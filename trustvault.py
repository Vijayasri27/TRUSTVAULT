"""
TrustVault — single-file document-sharing starter app
Run:
    python -m pip install flask
    python trustvault.py
Open:
    http://127.0.0.1:5000

DEMO ONLY:
- Uses SQLite and local private storage.
- Set TRUSTVAULT_SECRET to a long random secret before deployment.
- Use HTTPS and a production WSGI server in deployment.
- Audit logs are append-only through this app, but SQLite/local admin access
  can still alter them; this is NOT tamper-evident storage.
- Do not expose this demo directly to the public internet.
"""

import os
import re
import hmac
import hashlib
import secrets
import sqlite3
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from flask import (
    Flask, request, redirect, url_for, session, flash, abort,
    send_file, render_template_string, g
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "trustvault_private"
UPLOAD_DIR = DATA_DIR / "documents"
DB_PATH = DATA_DIR / "trustvault.sqlite3"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("TRUSTVAULT_SECRET", secrets.token_hex(32))
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB
ALLOWED_EXTENSIONS = {"pdf", "txt", "docx", "xlsx", "png", "jpg", "jpeg"}
ROLES = {"admin", "owner", "viewer"}
CATEGORIES = {"General", "HR", "Finance", "Legal", "Engineering", "Other"}


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.execute("PRAGMA foreign_keys = ON")
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('admin','owner','viewer')),
        created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS documents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        stored_name TEXT NOT NULL UNIQUE,
        original_name TEXT NOT NULL,
        owner_id INTEGER NOT NULL REFERENCES users(id),
        category TEXT NOT NULL,
        uploaded_at TEXT NOT NULL,
        sha256 TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS permissions (
        document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        can_read INTEGER NOT NULL DEFAULT 0,
        can_edit INTEGER NOT NULL DEFAULT 0,
        granted_by INTEGER NOT NULL REFERENCES users(id),
        granted_at TEXT NOT NULL,
        PRIMARY KEY(document_id, user_id),
        CHECK(can_edit = 0 OR can_read = 1)
    );
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        actor_id INTEGER REFERENCES users(id),
        action TEXT NOT NULL,
        document_id INTEGER,
        target_user_id INTEGER,
        detail TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL
    );
    """)
    # Convenient demo users, created only when the database is empty.
    count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if count == 0:
        demo_users = [
            ("admin", "AdminDemo!2026", "admin"),
            ("owner", "OwnerDemo!2026", "owner"),
            ("viewer", "ViewerDemo!2026", "viewer"),
        ]
        for username, password, role in demo_users:
            db.execute(
                "INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                (username, generate_password_hash(password), role, utc_now()),
            )
    db.commit()
    db.close()


def audit(action, document_id=None, target_user_id=None, detail=""):
    """Record an event; never provide an edit/delete route for audit entries."""
    actor_id = session.get("user_id")
    get_db().execute(
        """INSERT INTO audit_logs(actor_id,action,document_id,target_user_id,detail,created_at)
           VALUES(?,?,?,?,?,?)""",
        (actor_id, action, document_id, target_user_id, str(detail)[:500], utc_now()),
    )
    get_db().commit()


def current_user():
    if not session.get("user_id"):
        return None
    return get_db().execute(
        "SELECT id, username, role FROM users WHERE id=?",
        (session["user_id"],),
    ).fetchone()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def role_required(*roles):
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            user = current_user()
            if user["role"] not in roles:
                audit("ACCESS_DENIED", detail=f"Role {user['role']} blocked from {request.path}")
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator


def can_read_document(doc, user):
    if not user:
        return False
    if user["role"] == "admin" or doc["owner_id"] == user["id"]:
        return True
    perm = get_db().execute(
        "SELECT can_read FROM permissions WHERE document_id=? AND user_id=?",
        (doc["id"], user["id"]),
    ).fetchone()
    return bool(perm and perm["can_read"])


def can_edit_document(doc, user):
    if not user:
        return False
    if user["role"] == "admin" or doc["owner_id"] == user["id"]:
        return True
    perm = get_db().execute(
        "SELECT can_edit FROM permissions WHERE document_id=? AND user_id=?",
        (doc["id"], user["id"]),
    ).fetchone()
    return bool(perm and perm["can_edit"])


def get_document_or_404(doc_id):
    doc = get_db().execute("SELECT * FROM documents WHERE id=?", (doc_id,)).fetchone()
    if doc is None:
        abort(404)
    return doc


def document_access(doc_id, mode="read"):
    doc = get_document_or_404(doc_id)
    user = current_user()
    allowed = can_read_document(doc, user) if mode == "read" else can_edit_document(doc, user)
    if not allowed:
        audit("ACCESS_DENIED", document_id=doc_id, detail=f"Denied {mode} request")
        abort(403)
    return doc


def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(32)
    return session["_csrf"]


@app.before_request
def csrf_protect():
    if request.method == "POST":
        supplied = request.form.get("_csrf", "")
        expected = session.get("_csrf", "")
        if not expected or not hmac.compare_digest(supplied, expected):
            abort(400, "Invalid or missing CSRF token.")


@app.context_processor
def inject_template_helpers():
    return {"csrf_token": csrf_token, "user": current_user()}


TEMPLATE = r"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ title }} — TrustVault</title>
<style>
*{box-sizing:border-box}body{font-family:Arial,sans-serif;background:#f3f5f9;color:#172033;margin:0}
header{background:#13233f;color:white;padding:16px 5%;display:flex;justify-content:space-between;gap:16px;align-items:center;flex-wrap:wrap}
header a{color:#fff;text-decoration:none;margin-right:14px}main{max-width:1050px;margin:28px auto;padding:0 16px}
.card{background:white;padding:22px;border-radius:12px;box-shadow:0 4px 18px #15284a12;margin-bottom:18px}
h1,h2{margin-top:0}label{display:block;margin:12px 0 5px;font-weight:bold}
input,select,button{font:inherit;padding:10px;border:1px solid #ccd3df;border-radius:7px;max-width:100%}
input,select{width:100%}button,.btn{background:#2357b7;color:white;border:0;cursor:pointer;text-decoration:none;display:inline-block;padding:10px 14px;border-radius:7px;margin-top:10px}
.btn.secondary{background:#58677d}.danger{background:#a83232}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:10px;border-bottom:1px solid #e7ebf2;vertical-align:top}
.notice{padding:10px;background:#e7f5eb;border-radius:7px;margin:8px 0}.error{background:#fdeaea}
.small{color:#58677d;font-size:.92em}.row{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px}
.inline{display:inline}code{overflow-wrap:anywhere}
</style></head>
<body><header><div><strong>TrustVault</strong> — Secure Document Sharing</div>
<nav>{% if user %}<a href="{{ url_for('dashboard') }}">Documents</a>
{% if user.role == 'admin' %}<a href="{{ url_for('users') }}">Users</a><a href="{{ url_for('audit_logs') }}">Audit trail</a>{% endif %}
<span>{{ user.username }} ({{ user.role }})</span>
<form class="inline" method="post" action="{{ url_for('logout') }}"><input type="hidden" name="_csrf" value="{{ csrf_token() }}"><button class="secondary">Log out</button></form>
{% else %}<a href="{{ url_for('login') }}">Login</a>{% endif %}</nav></header>
<main>
{% for category,message in get_flashed_messages(with_categories=true) %}
<div class="notice {{ 'error' if category == 'error' else '' }}">{{ message }}</div>{% endfor %}
{{ body|safe }}
</main></body></html>
"""


def page(title, body, **context):
    return render_template_string(TEMPLATE, title=title,
                                  body=render_template_string(body, **context))


@app.route("/")
def index():
    return redirect(url_for("dashboard") if current_user() else url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        row = get_db().execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if row and check_password_hash(row["password_hash"], password):
            session.clear()
            session["user_id"] = row["id"]
            session["_csrf"] = secrets.token_urlsafe(32)
            audit("LOGIN_SUCCESS", detail=f"User {username} logged in")
            return redirect(url_for("dashboard"))
        # Failed login attempt is recorded without revealing which field was wrong.
        audit("LOGIN_FAILED", detail=f"Failed login for username {username[:80]}")
        flash("Invalid username or password.", "error")
    body = """
    <div class="card" style="max-width:520px;margin:auto"><h1>Sign in</h1>
    <p class="small">Demo accounts are listed below. Change these passwords before any real use.</p>
    <form method="post"><input type="hidden" name="_csrf" value="{{ csrf_token() }}">
    <label>Username</label><input name="username" required autocomplete="username">
    <label>Password</label><input type="password" name="password" required autocomplete="current-password">
    <button>Login</button></form>
    <hr><p><b>Admin:</b> admin / AdminDemo!2026</p>
    <p><b>Owner:</b> owner / OwnerDemo!2026</p>
    <p><b>Viewer:</b> viewer / ViewerDemo!2026</p></div>"""
    return page("Login", body)


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    audit("LOGOUT")
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    db, user = get_db(), current_user()
    query = request.args.get("q", "").strip()[:100]
    category = request.args.get("category", "")
    date_from, date_to = request.args.get("from", ""), request.args.get("to", "")
    # Parameterized queries prevent SQL injection.
    sql = """SELECT DISTINCT d.*, u.username AS owner_name FROM documents d
             JOIN users u ON u.id=d.owner_id
             LEFT JOIN permissions p ON p.document_id=d.id
             WHERE (d.owner_id=? OR ?='admin' OR (p.user_id=? AND p.can_read=1))"""
    params = [user["id"], user["role"], user["id"]]
    if query:
        sql += " AND (d.title LIKE ? OR u.username LIKE ?)"
        params += [f"%{query}%", f"%{query}%"]
    if category in CATEGORIES:
        sql += " AND d.category=?"
        params.append(category)
    if date_from:
        sql += " AND date(d.uploaded_at)>=date(?)"
        params.append(date_from)
    if date_to:
        sql += " AND date(d.uploaded_at)<=date(?)"
        params.append(date_to)
    sql += " ORDER BY d.uploaded_at DESC"
    docs = db.execute(sql, params).fetchall()
    body = """
    <div class="card"><h1>Your documents</h1>
    <p class="small">Only documents you own, administer, or have been granted access to are listed.</p>
    <a class="btn" href="{{ url_for('upload') }}">Upload document</a>
    <form method="get"><div class="row">
    <div><label>Search name or owner</label><input name="q" value="{{ q }}"></div>
    <div><label>Category</label><select name="category"><option value="">All categories</option>
    {% for c in categories %}<option {{ 'selected' if c==category else '' }}>{{ c }}</option>{% endfor %}</select></div>
    <div><label>Uploaded from</label><input type="date" name="from" value="{{ date_from }}"></div>
    <div><label>Uploaded to</label><input type="date" name="to" value="{{ date_to }}"></div></div><button>Search</button></form></div>
    <div class="card"><table><thead><tr><th>Document</th><th>Owner</th><th>Category</th><th>Uploaded</th><th>Actions</th></tr></thead><tbody>
    {% for d in docs %}<tr><td>{{ d.title }}<br><span class="small">{{ d.original_name }}</span></td>
    <td>{{ d.owner_name }}</td><td>{{ d.category }}</td><td>{{ d.uploaded_at }}</td><td>
    <a href="{{ url_for('download', doc_id=d.id) }}">Download</a><br>
    {% if d.owner_id==user.id or user.role=='admin' %}<a href="{{ url_for('manage_permissions',doc_id=d.id) }}">Permissions</a><br>{% endif %}
    {% if d.owner_id==user.id or user.role=='admin' %}<a href="{{ url_for('edit_document',doc_id=d.id) }}">Edit details</a>{% endif %}
    </td></tr>{% else %}<tr><td colspan="5">No documents found.</td></tr>{% endfor %}
    </tbody></table></div>"""
    return page("Documents", body, docs=docs, q=query, category=category,
                categories=sorted(CATEGORIES), date_from=date_from, date_to=date_to)


@app.route("/upload", methods=["GET", "POST"])
@role_required("admin", "owner")
def upload():
    if request.method == "POST":
        f = request.files.get("document")
        title = request.form.get("title", "").strip()[:150]
        category = request.form.get("category", "General")
        if not f or not f.filename or not title:
            flash("Choose a file and enter a title.", "error")
            return redirect(url_for("upload"))
        original = secure_filename(f.filename)
        if not original or "." not in original:
            flash("Invalid filename.", "error")
            return redirect(url_for("upload"))
        ext = original.rsplit(".", 1)[1].lower()
        if ext not in ALLOWED_EXTENSIONS:
            audit("UPLOAD_REJECTED", detail=f"Rejected extension: {ext}")
            flash("File type not allowed.", "error")
            return redirect(url_for("upload"))
        if category not in CATEGORIES:
            category = "General"
        data = f.read(app.config["MAX_CONTENT_LENGTH"] + 1)
        if not data or len(data) > app.config["MAX_CONTENT_LENGTH"]:
            flash("File is empty or too large (maximum 10 MB).", "error")
            return redirect(url_for("upload"))
        # Random storage name prevents path traversal and name collisions.
        stored = secrets.token_hex(24) + "." + ext
        digest = hashlib.sha256(data).hexdigest()
        path = UPLOAD_DIR / stored
        path.write_bytes(data)
        db = get_db()
        try:
            cur = db.execute(
                """INSERT INTO documents(title,stored_name,original_name,owner_id,category,uploaded_at,sha256)
                   VALUES(?,?,?,?,?,?,?)""",
                (title, stored, original, current_user()["id"], category, utc_now(), digest),
            )
            doc_id = cur.lastrowid
            audit("UPLOAD", document_id=doc_id, detail=f"sha256={digest}; bytes={len(data)}")
            db.commit()
        except Exception:
            path.unlink(missing_ok=True)
            db.rollback()
            raise
        flash("Document uploaded.")
        return redirect(url_for("dashboard"))
    body = """
    <div class="card"><h1>Upload document</h1><form method="post" enctype="multipart/form-data">
    <input type="hidden" name="_csrf" value="{{ csrf_token() }}">
    <label>Document title</label><input name="title" maxlength="150" required>
    <label>Category</label><select name="category">{% for c in categories %}<option>{{ c }}</option>{% endfor %}</select>
    <label>File (PDF, TXT, DOCX, XLSX, PNG, JPG; max 10 MB)</label><input type="file" name="document" required>
    <button>Upload</button></form></div>"""
    return page("Upload", body, categories=sorted(CATEGORIES))


@app.route("/download/<int:doc_id>")
@login_required
def download(doc_id):
    doc = document_access(doc_id, "read")
    path = UPLOAD_DIR / doc["stored_name"]
    if not path.is_file() or path.resolve().parent != UPLOAD_DIR.resolve():
        abort(404)
    audit("DOWNLOAD", document_id=doc_id)
    # Attachment disposition; never serve user documents as inline HTML.
    return send_file(path, as_attachment=True, download_name=doc["original_name"],
                     mimetype="application/octet-stream", max_age=0)


@app.route("/document/<int:doc_id>/edit", methods=["GET", "POST"])
@login_required
def edit_document(doc_id):
    doc = document_access(doc_id, "edit")
    if request.method == "POST":
        title = request.form.get("title", "").strip()[:150]
        category = request.form.get("category", "General")
        if not title or category not in CATEGORIES:
            flash("Provide a title and valid category.", "error")
            return redirect(url_for("edit_document", doc_id=doc_id))
        get_db().execute("UPDATE documents SET title=?,category=? WHERE id=?",
                         (title, category, doc_id))
        audit("DOCUMENT_UPDATED", document_id=doc_id, detail=f"title={title}; category={category}")
        get_db().commit()
        flash("Document details updated.")
        return redirect(url_for("dashboard"))
    body = """
    <div class="card"><h1>Edit document details</h1><form method="post">
    <input type="hidden" name="_csrf" value="{{ csrf_token() }}">
    <label>Title</label><input name="title" value="{{ doc.title }}" required maxlength="150">
    <label>Category</label><select name="category">{% for c in categories %}<option {{ 'selected' if c==doc.category else '' }}>{{ c }}</option>{% endfor %}</select>
    <button>Save</button></form></div>"""
    return page("Edit", body, doc=doc, categories=sorted(CATEGORIES))


@app.route("/document/<int:doc_id>/permissions", methods=["GET", "POST"])
@login_required
def manage_permissions(doc_id):
    doc = get_document_or_404(doc_id)
    user = current_user()
    if user["role"] != "admin" and doc["owner_id"] != user["id"]:
        audit("ACCESS_DENIED", document_id=doc_id, detail="Permission management denied")
        abort(403)
    db = get_db()
    if request.method == "POST":
        action = request.form.get("action")
        username = request.form.get("username", "").strip()
        target = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if not target:
            flash("User not found.", "error")
            return redirect(url_for("manage_permissions", doc_id=doc_id))
        if target["id"] == doc["owner_id"]:
            flash("The owner already has access.", "error")
            return redirect(url_for("manage_permissions", doc_id=doc_id))
        if action == "revoke":
            db.execute("DELETE FROM permissions WHERE document_id=? AND user_id=?",
                       (doc_id, target["id"]))
            audit("PERMISSION_REVOKED", doc_id, target["id"], f"Revoked access for {username}")
        elif action == "grant":
            can_read_flag = 1
            can_edit_flag = 1 if request.form.get("can_edit") == "yes" else 0
            db.execute("""INSERT INTO permissions(document_id,user_id,can_read,can_edit,granted_by,granted_at)
                          VALUES(?,?,?,?,?,?)
                          ON CONFLICT(document_id,user_id) DO UPDATE SET
                          can_read=excluded.can_read, can_edit=excluded.can_edit,
                          granted_by=excluded.granted_by, granted_at=excluded.granted_at""",
                       (doc_id, target["id"], can_read_flag, can_edit_flag, user["id"], utc_now()))
            audit("PERMISSION_GRANTED", doc_id, target["id"],
                  f"Granted read={'yes'} edit={bool(can_edit_flag)} to {username}")
        else:
            abort(400)
        db.commit()
        flash("Permissions updated.")
        return redirect(url_for("manage_permissions", doc_id=doc_id))
    perms = db.execute("""SELECT p.*,u.username FROM permissions p JOIN users u ON u.id=p.user_id
                          WHERE p.document_id=? ORDER BY u.username""", (doc_id,)).fetchall()
    users_list = db.execute("SELECT username,role FROM users WHERE id!=? ORDER BY username",
                            (doc["owner_id"],)).fetchall()
    body = """
    <div class="card"><h1>Permissions: {{ doc.title }}</h1>
    <p>Only named users listed here can read this document (besides its owner and administrators).</p>
    <form method="post"><input type="hidden" name="_csrf" value="{{ csrf_token() }}">
    <label>Username</label><select name="username" required>{% for u in users_list %}<option value="{{ u.username }}">{{ u.username }} ({{ u.role }})</option>{% endfor %}</select>
    <label><input style="width:auto" type="checkbox" name="can_edit" value="yes"> Allow editing document details</label>
    <button name="action" value="grant">Grant / update access</button></form>
    <h2>Current access</h2><table><tr><th>User</th><th>Read</th><th>Edit</th><th>Action</th></tr>
    {% for p in perms %}<tr><td>{{ p.username }}</td><td>{{ 'Yes' if p.can_read else 'No' }}</td><td>{{ 'Yes' if p.can_edit else 'No' }}</td>
    <td><form method="post"><input type="hidden" name="_csrf" value="{{ csrf_token() }}"><input type="hidden" name="username" value="{{ p.username }}"><button class="danger" name="action" value="revoke">Revoke</button></form></td></tr>
    {% else %}<tr><td colspan="4">No additional users have access.</td></tr>{% endfor %}</table>
    <p class="small">Access is checked on every request. Revocation therefore applies to future requests immediately.</p></div>"""
    return page("Permissions", body, doc=doc, perms=perms, users_list=users_list)


@app.route("/users", methods=["GET", "POST"])
@role_required("admin")
def users():
    db = get_db()
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,40}", username):
            flash("Username must be 3–40 characters: letters, numbers, dot, underscore, hyphen.", "error")
        elif len(password) < 12:
            flash("Password must be at least 12 characters.", "error")
        elif role not in ROLES:
            flash("Invalid role.", "error")
        else:
            try:
                cur = db.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                                 (username, generate_password_hash(password), role, utc_now()))
                audit("USER_CREATED", target_user_id=cur.lastrowid, detail=f"Created {username} as {role}")
                db.commit()
                flash("User created.")
            except sqlite3.IntegrityError:
                flash("That username already exists.", "error")
        return redirect(url_for("users"))
    all_users = db.execute("SELECT id,username,role,created_at FROM users ORDER BY id").fetchall()
    body = """
    <div class="card"><h1>User administration</h1><form method="post">
    <input type="hidden" name="_csrf" value="{{ csrf_token() }}">
    <label>Username</label><input name="username" required minlength="3" maxlength="40">
    <label>Temporary password (at least 12 characters)</label><input type="password" name="password" required minlength="12">
    <label>Role</label><select name="role">{% for r in roles %}<option>{{ r }}</option>{% endfor %}</select>
    <button>Create user</button></form></div>
    <div class="card"><h2>Users</h2><table><tr><th>ID</th><th>Username</th><th>Role</th><th>Created</th></tr>
    {% for u in users %}<tr><td>{{ u.id }}</td><td>{{ u.username }}</td><td>{{ u.role }}</td><td>{{ u.created_at }}</td></tr>{% endfor %}
    </table></div>"""
    return page("Users", body, users=all_users, roles=sorted(ROLES))


@app.route("/audit")
@role_required("admin")
def audit_logs():
    db = get_db()
    rows = db.execute("""SELECT a.*,u.username,tu.username AS target_username
                         FROM audit_logs a LEFT JOIN users u ON u.id=a.actor_id
                         LEFT JOIN users tu ON tu.id=a.target_user_id
                         ORDER BY a.id DESC LIMIT 500""").fetchall()
    body = """
    <div class="card"><h1>Audit trail</h1><p class="small">Latest 500 events. No edit/delete route is provided.</p>
    <table><tr><th>Time</th><th>Actor</th><th>Action</th><th>Document</th><th>Target user</th><th>Detail</th></tr>
    {% for r in rows %}<tr><td>{{ r.created_at }}</td><td>{{ r.username or 'Unknown' }}</td>
    <td>{{ r.action }}</td><td>{{ r.document_id or '—' }}</td><td>{{ r.target_username or '—' }}</td><td>{{ r.detail }}</td></tr>
    {% else %}<tr><td colspan="6">No events yet.</td></tr>{% endfor %}</table></div>"""
    return page("Audit trail", body, rows=rows)


@app.errorhandler(403)
def forbidden(_error):
    return page("Access denied", """
    <div class="card"><h1>403 — Access denied</h1>
    <p>You do not have permission to perform this action.</p><a class="btn" href="{{ url_for('dashboard') }}">Back to documents</a></div>
    """), 403


@app.errorhandler(404)
def not_found(_error):
    return page("Not found", """
    <div class="card"><h1>404 — Not found</h1><p>The requested resource does not exist.</p>
    <a class="btn" href="{{ url_for('dashboard') }}">Back to documents</a></div>
    """), 404


@app.errorhandler(413)
def too_large(_error):
    return page("File too large", """
    <div class="card"><h1>File too large</h1><p>Maximum upload size is 10 MB.</p>
    <a class="btn" href="{{ url_for('upload') }}">Try again</a></div>
    """), 413


# Small automated authorization checks for the core access-control rule.
def run_security_smoke_tests():
    with app.app_context():
        db = get_db()
        users = db.execute("SELECT id,username,role FROM users").fetchall()
        by_name = {u["username"]: u for u in users}
        # If default demo accounts were changed, these checks are skipped.
        if not {"owner", "viewer", "admin"}.issubset(by_name):
            print("Security smoke tests skipped: default demo accounts not found.")
            return
        fake_doc = {"id": -1, "owner_id": by_name["owner"]["id"]}
        assert can_read_document(fake_doc, by_name["owner"])
        assert can_edit_document(fake_doc, by_name["owner"])
        assert not can_read_document(fake_doc, by_name["viewer"])
        assert not can_edit_document(fake_doc, by_name["viewer"])
        assert can_read_document(fake_doc, by_name["admin"])
        assert can_edit_document(fake_doc, by_name["admin"])
        print("Core authorization smoke tests passed.")


if __name__ == "__main__":
    init_db()
    run_security_smoke_tests()
    print("TrustVault running at http://127.0.0.1:5000")
    print("Demo accounts: admin/AdminDemo!2026, owner/OwnerDemo!2026, viewer/ViewerDemo!2026")
    app.run(host="127.0.0.1", port=5000, debug=False)
