import os
import sqlite3
import secrets
import functools
from datetime import datetime
from pathlib import Path

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, send_from_directory,
    g, jsonify, abort
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# ---------------------------
# 基本設定
# ---------------------------

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

DB_PATH = BASE_DIR / "the_outfit.db"

APP_ENV = os.environ.get("APP_ENV", "dev").lower()
DEBUG = APP_ENV != "prod"

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config["UPLOAD_FOLDER"] = str(UPLOAD_DIR)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10MB

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}


# ---------------------------
# DB ヘルパ
# ---------------------------

def get_db():
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            user TEXT NOT NULL,
            created_at TEXT NOT NULL,
            votes INTEGER NOT NULL DEFAULT 0
        );
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS votes (
            user TEXT NOT NULL,
            post_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (user, post_id)
        );
        """
    )
    db.commit()


# ---------------------------
# CSRF
# ---------------------------

def generate_csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def validate_csrf():
    form_token = request.form.get("csrf_token", "")
    session_token = session.get("_csrf_token")
    if not form_token or not session_token or form_token != session_token:
        abort(400, description="Invalid CSRF token")


app.jinja_env.globals["csrf_token"] = generate_csrf_token


# ---------------------------
# ログイン状態の判定（★ DB にユーザーがいるか毎回確認）
# ---------------------------

def fetch_db_user(username):
    """users テーブルに存在する username だけを有効とする"""
    if not username:
        return None
    db = get_db()
    row = db.execute(
        "SELECT username FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    if row is None:
        return None
    return row["username"]


@app.before_request
def load_logged_in_user():
    """
    毎リクエストで session から username を取り出し、
    DB に実在しなければ session から削除して「未ログイン扱い」にする。
    これにより、DB からユーザー削除後に古いセッションだけ残っていても、
    アップロードや投票は一切できなくなる。
    """
    username = session.get("user")
    real_user = fetch_db_user(username)

    if real_user is None and "user" in session:
        # DB から消えているセッションは破棄
        session.pop("user", None)

    g.user = real_user  # None か 実在ユーザー名


def login_required(view):
    """
    アップロードなど HTML 画面で使う用。
    DB にいないユーザーも g.user は None になるのでブロックされる。
    """
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            # next で元のURLに戻れるようにする
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def login_required_api(view):
    """
    fetch() から叩かれる API 用。
    未ログイン or DBにいないユーザーは JSON で 401 を返す。
    """
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            # JS から扱いやすいように JSON を返す
            return jsonify({"ok": False, "reason": "auth"}), 401
        return view(*args, **kwargs)
    return wrapped


# ---------------------------
# ユーティリティ
# ---------------------------

def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


# ---------------------------
# ルーティング
# ---------------------------

@app.route("/")
def index():
    init_db()
    db = get_db()

    posts = db.execute(
        """
        SELECT id, filename, user, votes, created_at
        FROM posts
        ORDER BY votes DESC, created_at DESC
        """
    ).fetchall()

    if g.user:
        rows = db.execute(
            "SELECT post_id FROM votes WHERE user = ?",
            (g.user,),
        ).fetchall()
        voted_ids = {row["post_id"] for row in rows}
    else:
        voted_ids = set()

    # テンプレート側の条件表示用
    return render_template(
        "home.html",
        posts=posts,
        is_logged_in=g.user is not None,
        user=g.user,
        voted_ids=voted_ids,
    )


@app.route("/register", methods=["GET", "POST"])
def register():
    init_db()
    if request.method == "POST":
        validate_csrf()
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        if not username or not password:
            return render_template(
                "register.html",
                error="ユーザー名とパスワードを入力してください。",
            )

        db = get_db()
        exists = db.execute(
            "SELECT 1 FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        if exists:
            return render_template(
                "register.html",
                error="このユーザー名は既に使われています。",
            )

        db.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
            (username, generate_password_hash(password), datetime.utcnow().isoformat()),
        )
        db.commit()
        session["user"] = username
        return redirect(url_for("index"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    init_db()
    if request.method == "POST":
        validate_csrf()
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        next_url = request.args.get("next") or url_for("index")

        db = get_db()
        row = db.execute(
            "SELECT username, password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()

        if row is None or not check_password_hash(row["password_hash"], password):
            return render_template(
                "login.html",
                error="ユーザー名またはパスワードが違います。",
            )

        session["user"] = row["username"]
        return redirect(next_url)

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    validate_csrf()
    session.pop("user", None)
    return redirect(url_for("index"))


@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    init_db()
    if request.method == "POST":
        validate_csrf()
        if "photo" not in request.files:
            return render_template(
                "upload.html",
                error="ファイルが選択されていません。",
            )

        file = request.files["photo"]
        if file.filename == "":
            return render_template(
                "upload.html",
                error="ファイル名が空です。",
            )

        if not allowed_file(file.filename):
            return render_template(
                "upload.html",
                error="対応していないファイル形式です。（png/jpg/jpeg/webp）",
            )

        filename = secure_filename(file.filename)
        # ランダムなプレフィックスを付けて衝突防止
        random_prefix = secrets.token_hex(8)
        final_name = f"{random_prefix}_{filename}"
        save_path = UPLOAD_DIR / final_name
        file.save(save_path)

        db = get_db()
        db.execute(
            """
            INSERT INTO posts (filename, user, created_at, votes)
            VALUES (?, ?, ?, 0)
            """,
            (final_name, g.user, datetime.utcnow().isoformat()),
        )
        db.commit()
        return redirect(url_for("index"))

    return render_template("upload.html")


@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


# ---------------------------
# 投票 API
# ---------------------------

@app.route("/vote/<int:post_id>", methods=["POST"])
@login_required_api
def vote(post_id):
    init_db()
    validate_csrf()

    db = get_db()
    # 対象投稿の存在確認
    post = db.execute(
        "SELECT id FROM posts WHERE id = ?",
        (post_id,),
    ).fetchone()
    if post is None:
        return jsonify({"ok": False, "reason": "not_found"}), 404

    # 既に投票済みなら何もしない
    already = db.execute(
        "SELECT 1 FROM votes WHERE user = ? AND post_id = ?",
        (g.user, post_id),
    ).fetchone()
    if already:
        cur_votes = db.execute(
            "SELECT votes FROM posts WHERE id = ?",
            (post_id,),
        ).fetchone()["votes"]
        return jsonify(
            {"ok": True, "post_id": post_id, "votes": cur_votes, "voted": True}
        )

    db.execute(
        "INSERT INTO votes (user, post_id, created_at) VALUES (?, ?, ?)",
        (g.user, post_id, datetime.utcnow().isoformat()),
    )
    db.execute(
        "UPDATE posts SET votes = votes + 1 WHERE id = ?",
        (post_id,),
    )
    db.commit()

    new_votes = db.execute(
        "SELECT votes FROM posts WHERE id = ?",
        (post_id,),
    ).fetchone()["votes"]

    return jsonify(
        {"ok": True, "post_id": post_id, "votes": new_votes, "voted": True}
    )


@app.route("/unvote/<int:post_id>", methods=["POST"])
@login_required_api
def unvote(post_id):
    init_db()
    validate_csrf()

    db = get_db()
    post = db.execute(
        "SELECT id FROM posts WHERE id = ?",
        (post_id,),
    ).fetchone()
    if post is None:
        return jsonify({"ok": False, "reason": "not_found"}), 404

    exists = db.execute(
        "SELECT 1 FROM votes WHERE user = ? AND post_id = ?",
        (g.user, post_id),
    ).fetchone()
    if not exists:
        cur_votes = db.execute(
            "SELECT votes FROM posts WHERE id = ?",
            (post_id,),
        ).fetchone()["votes"]
        return jsonify(
            {"ok": True, "post_id": post_id, "votes": cur_votes, "voted": False}
        )

    db.execute(
        "DELETE FROM votes WHERE user = ? AND post_id = ?",
        (g.user, post_id),
    )
    db.execute(
        "UPDATE posts SET votes = MAX(votes - 1, 0) WHERE id = ?",
        (post_id,),
    )
    db.commit()

    new_votes = db.execute(
        "SELECT votes FROM posts WHERE id = ?",
        (post_id,),
    ).fetchone()["votes"]

    return jsonify(
        {"ok": True, "post_id": post_id, "votes": new_votes, "voted": False}
    )


# ---------------------------
# エントリポイント
# ---------------------------

if __name__ == "__main__":
    with app.app_context():
        init_db()
    app.run(host="0.0.0.0", port=5000, debug=DEBUG)
