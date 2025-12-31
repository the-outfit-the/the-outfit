import os
import re
import sqlite3
import uuid
import time
import secrets
from datetime import timedelta

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, abort, send_from_directory, jsonify
)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Renderで有料 + Disk を使うときだけ DATA_DIR=/var/data を設定する
DATA_DIR = os.environ.get("DATA_DIR", BASE_DIR)

DB_PATH = os.path.join(DATA_DIR, "the_outfit.db")
UPLOAD_FOLDER = os.path.join(DATA_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}
MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5MB

APP_ENV = os.environ.get("APP_ENV", "dev").lower()  # dev / prod
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-me")  # prodでは必ず上書き

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_\-]{3,20}$")  # 3-20文字

CSP = (
    "default-src 'self'; "
    "img-src 'self' data:; "
    "style-src 'self' 'unsafe-inline'; "
    "script-src 'self' 'unsafe-inline'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'; "
)

_RATE_BUCKET = {}
RATE_WINDOW_SEC = 60
RATE_LIMITS = {
    "login": 20,
    "register": 10,
    "upload": 20,
}

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.permanent_session_lifetime = timedelta(days=7)

app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = (APP_ENV == "prod")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            name TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user TEXT NOT NULL,
            filename TEXT NOT NULL,
            votes INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS votes (
            user TEXT NOT NULL,
            post_id INTEGER NOT NULL,
            PRIMARY KEY (user, post_id)
        )
    """)

    conn.commit()
    conn.close()


init_db()


def client_ip() -> str:
    return request.remote_addr or "unknown"


def rate_limit(action: str):
    limit = RATE_LIMITS.get(action)
    if not limit:
        return

    ip = client_ip()
    now = time.time()
    key = (ip, action)

    bucket = _RATE_BUCKET.get(key, [])
    bucket = [t for t in bucket if now - t < RATE_WINDOW_SEC]

    if len(bucket) >= limit:
        abort(429)

    bucket.append(now)
    _RATE_BUCKET[key] = bucket


def allowed_ext(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def require_login():
    if "user" not in session:
        return redirect(url_for("login", next=request.path))
    return None


def csrf_get_token() -> str:
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def csrf_validate():
    sent = request.form.get("csrf_token", "")
    token = session.get("csrf_token", "")
    if not token or not sent or not secrets.compare_digest(token, sent):
        abort(400)


def is_ajax_json_request() -> bool:
    # home.html から fetch で投票を投げるときに付けるヘッダで判定
    return (
        request.headers.get("X-Requested-With", "") == "fetch"
        or "application/json" in (request.headers.get("Accept", "") or "")
    )


@app.context_processor
def inject_csrf():
    return {"csrf_token": csrf_get_token()}


@app.after_request
def set_security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    resp.headers["Content-Security-Policy"] = CSP

    if APP_ENV == "prod" and request.is_secure:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return resp


@app.errorhandler(429)
def too_many(_):
    return "Too Many Requests", 429


@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


@app.route("/", methods=["GET"])
def home():
    user = session.get("user")

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT id, user, filename, votes
        FROM posts
        ORDER BY votes DESC, created_at DESC
    """)
    posts = cur.fetchall()

    voted_ids = set()
    if user:
        cur.execute("SELECT post_id FROM votes WHERE user = ?", (user,))
        voted_ids = {row["post_id"] for row in cur.fetchall()}

    conn.close()

    return render_template(
        "home.html",
        user=user,
        posts=posts,
        voted_ids=voted_ids,
        is_logged_in=bool(user)
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        rate_limit("login")
        csrf_validate()

        name = request.form.get("name", "").strip()
        password = request.form.get("password", "")

        if not name or not password:
            flash("ユーザー名とパスワードを入力してください。")
            return render_template("login.html")

        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT password_hash FROM users WHERE name = ?", (name,))
        row = cur.fetchone()
        conn.close()

        if row and check_password_hash(row["password_hash"], password):
            session.clear()
            session["user"] = name
            session.permanent = True
            session["csrf_token"] = secrets.token_urlsafe(32)

            nxt = request.args.get("next") or url_for("home")
            if not nxt.startswith("/"):
                nxt = url_for("home")
            return redirect(nxt)

        flash("ユーザー名またはパスワードが違います。")
        return render_template("login.html")

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        rate_limit("register")
        csrf_validate()

        name = request.form.get("name", "").strip()
        password = request.form.get("password", "")

        if not USERNAME_RE.match(name):
            flash("ユーザー名は 3〜20文字（英数字/ _ / -）で入力してください。")
            return render_template("register.html")

        if len(password) < 8:
            flash("パスワードは8文字以上にしてください。")
            return render_template("register.html")

        password_hash = generate_password_hash(password, method="pbkdf2:sha256", salt_length=16)

        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM users WHERE name = ?", (name,))
        if cur.fetchone():
            conn.close()
            flash("このユーザー名はすでに使用されています。")
            return render_template("register.html")

        cur.execute("INSERT INTO users (name, password_hash) VALUES (?, ?)", (name, password_hash))
        conn.commit()
        conn.close()

        session.clear()
        session["user"] = name
        session.permanent = True
        session["csrf_token"] = secrets.token_urlsafe(32)
        return redirect(url_for("home"))

    return render_template("register.html")


@app.route("/upload", methods=["GET", "POST"])
def upload():
    r = require_login()
    if r:
        return r

    if request.method == "POST":
        rate_limit("upload")
        csrf_validate()

        file = request.files.get("image")
        if not file or file.filename == "":
            flash("ファイルが選択されていません。")
            return render_template("upload.html")

        if not allowed_ext(file.filename):
            flash("画像ファイル（png/jpg/jpeg/gif/webp）のみアップロードできます。")
            return render_template("upload.html")

        ext = file.filename.rsplit(".", 1)[1].lower()
        filename = secure_filename(f"{uuid.uuid4().hex}.{ext}")
        file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO posts (user, filename, votes) VALUES (?, ?, 0)",
            (session["user"], filename)
        )
        conn.commit()
        conn.close()

        return redirect(url_for("home"))

    return render_template("upload.html")


@app.route("/vote/<int:post_id>", methods=["POST"])
def vote(post_id):
    r = require_login()
    if r:
        return r
    csrf_validate()

    user = session["user"]
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT 1 FROM votes WHERE user = ? AND post_id = ?", (user, post_id))
    already = cur.fetchone()

    if not already:
        cur.execute("INSERT INTO votes (user, post_id) VALUES (?, ?)", (user, post_id))
        cur.execute("UPDATE posts SET votes = votes + 1 WHERE id = ?", (post_id,))
        conn.commit()

    # AjaxならJSONで返す（ページをリロードしない）
    if is_ajax_json_request():
        cur.execute("SELECT votes FROM posts WHERE id = ?", (post_id,))
        row = cur.fetchone()
        conn.close()
        return jsonify({"ok": True, "post_id": post_id, "votes": int(row["votes"]) if row else 0, "voted": True})

    conn.close()
    return redirect(url_for("home"))


@app.route("/unvote/<int:post_id>", methods=["POST"])
def unvote(post_id):
    r = require_login()
    if r:
        return r
    csrf_validate()

    user = session["user"]
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT 1 FROM votes WHERE user = ? AND post_id = ?", (user, post_id))
    exists = cur.fetchone()

    if exists:
        cur.execute("DELETE FROM votes WHERE user = ? AND post_id = ?", (user, post_id))
        cur.execute(
            "UPDATE posts SET votes = CASE WHEN votes > 0 THEN votes - 1 ELSE 0 END WHERE id = ?",
            (post_id,)
        )
        conn.commit()

    if is_ajax_json_request():
        cur.execute("SELECT votes FROM posts WHERE id = ?", (post_id,))
        row = cur.fetchone()
        conn.close()
        return jsonify({"ok": True, "post_id": post_id, "votes": int(row["votes"]) if row else 0, "voted": False})

    conn.close()
    return redirect(url_for("home"))


@app.route("/logout", methods=["POST"])
def logout():
    csrf_validate()
    session.clear()
    return redirect(url_for("home"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
