import os
import sqlite3
import secrets
import functools
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, send_from_directory,
    g, jsonify, abort
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# ---------------------------
# 保存先（Render対策）
#   - 永続Diskがあれば DATA_DIR が入る
#   - 無ければ /tmp（揮発だが動作はする）
# ---------------------------

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("DATA_DIR", "/tmp")).resolve()
DATA_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = Path(os.environ.get("DB_PATH", str(DATA_DIR / "the_outfit.db")))
UPLOAD_DIR = Path(os.environ.get("UPLOAD_DIR", str(DATA_DIR / "uploads")))
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

APP_ENV = os.environ.get("APP_ENV", "dev").lower()
DEBUG = APP_ENV != "prod"

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config["UPLOAD_FOLDER"] = str(UPLOAD_DIR)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10MB

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}
SUPPORTED_LANGS = ("ja", "en")

TRANSLATIONS = {
    "ja": {
        # common
        "site_name": "The Outfit",
        "lookbook": "ルックブック",
        "ranking": "ランキング",
        "ranked_looks": "ランキング",
        "curated_by_votes": "投票で決まる · リアルタイム",
        "guest": "ゲスト",

        "upload": "投稿",
        "login": "ログイン",
        "logout": "ログアウト",
        "register": "新規登録",

        "vote": "投票",
        "remove_vote": "投票取消",
        "login_required": "ログインが必要です",
        "login_to_vote": "投票するにはログインしてください。",
        "login_to_continue": "続行するにはログインしてください。",

        "voted": "投票しました",
        "unvoted": "取り消しました",
        "your_vote_counted": "投票を受け付けました。",
        "vote_removed": "投票を取り消しました。",
        "error": "エラー",
        "try_again": "もう一度お試しください。",

        "close_hint": "クリックで閉じる",
        "no_looks": "まだ投稿がありません。最初の1枚を投稿してみよう。",

        # intro
        "intro_kicker": "エディトリアル · コミュニティランキング",
        "intro_title": "投稿して、投票して、ランクイン。",
        "intro_desc_1": "は、世界中のファッション写真が集まる",
        "intro_desc_2": "投票型ルックブック",
        "intro_desc_3": "です。見るだけならログイン不要。投票・投稿はログイン後にできます。",
        "how_it_works": "このサイトについて",
        "can_do": "できること：",
        "can_view": "ランキング閲覧：誰でもOK（ログイン不要）",
        "can_vote": "投票：ログイン必須（1人1票・取消可）",
        "can_post": "投稿：ログイン必須（あなたの“今日の一枚”を世界へ）",
        "step_1": "投稿",
        "step_2": "投票",
        "step_3": "ランク",
        "view_ranking": "ランキングを見る",
    },
    "en": {
        # common
        "site_name": "The Outfit",
        "lookbook": "LOOKBOOK",
        "ranking": "RANKING",
        "ranked_looks": "RANKED LOOKS",
        "curated_by_votes": "CURATED BY VOTES · LIVE FEED",
        "guest": "GUEST",

        "upload": "UPLOAD",
        "login": "LOGIN",
        "logout": "LOGOUT",
        "register": "REGISTER",

        "vote": "VOTE",
        "remove_vote": "REMOVE VOTE",
        "login_required": "LOGIN REQUIRED",
        "login_to_vote": "Login to vote.",
        "login_to_continue": "Login to continue.",

        "voted": "VOTED",
        "unvoted": "UNVOTED",
        "your_vote_counted": "Your vote is counted.",
        "vote_removed": "Vote removed.",
        "error": "ERROR",
        "try_again": "Please try again.",

        "close_hint": "CLICK ANYWHERE TO CLOSE",
        "no_looks": "No looks yet. Be the first to curate your page.",

        # intro
        "intro_kicker": "EDITORIAL · COMMUNITY RANKING",
        "intro_title": "POST OUTFITS. VOTE. RANK.",
        "intro_desc_1": "is a vote-based lookbook where fashion photos from around the world compete.",
        "intro_desc_2": "",
        "intro_desc_3": "Browse without login. Vote & post after login.",
        "how_it_works": "WHAT IS THIS SITE?",
        "can_do": "What you can do:",
        "can_view": "View ranking: anyone (no login)",
        "can_vote": "Vote: login required (1 per person, removable)",
        "can_post": "Post: login required (share your look)",
        "step_1": "UPLOAD",
        "step_2": "VOTE",
        "step_3": "TOP RANK",
        "view_ranking": "VIEW RANKING",
    },
}


# ---------------------------
# i18n helpers
# ---------------------------

def get_lang() -> str:
    lang = session.get("lang")
    if lang in SUPPORTED_LANGS:
        return lang
    return "ja"


def t(key: str, **kwargs) -> str:
    lang = get_lang()
    table = TRANSLATIONS.get(lang, TRANSLATIONS["ja"])
    text = table.get(key, key)
    if kwargs:
        try:
            text = text.format(**kwargs)
        except Exception:
            pass
    return text


def _safe_next_url(next_url: str) -> str:
    """
    Open redirect対策：相対パスのみ許可
    """
    if not next_url:
        return url_for("index")
    try:
        parsed = urlparse(next_url)
        # 外部URL（scheme/hostあり）は拒否
        if parsed.scheme or parsed.netloc:
            return url_for("index")
        if not next_url.startswith("/"):
            return url_for("index")
        return next_url
    except Exception:
        return url_for("index")


@app.context_processor
def inject_i18n():
    def set_lang_url(code: str) -> str:
        # 今見てるページへ戻す（?lang=...等も含む）
        return url_for("set_lang", code=code, next=request.full_path)
    return {
        "t": t,
        "lang_code": get_lang(),
        "set_lang_url": set_lang_url,
    }


@app.route("/lang/<code>")
def set_lang(code):
    if code in SUPPORTED_LANGS:
        session["lang"] = code
    next_url = request.args.get("next") or request.referrer or url_for("index")
    return redirect(_safe_next_url(next_url))


# ---------------------------
# DB ヘルパ
# ---------------------------

def get_db():
    if "db" not in g:
        # Gunicorn/Render環境での安定化
        conn = sqlite3.connect(DB_PATH, timeout=5, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def _migrate_posts_add_title(db):
    """
    既存DBに title カラムが無い場合だけ追加（SQLiteの安全な簡易マイグレーション）
    """
    cols = [r["name"] for r in db.execute("PRAGMA table_info(posts)").fetchall()]
    if "title" not in cols:
        db.execute("ALTER TABLE posts ADD COLUMN title TEXT")
        db.commit()


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
            title TEXT,
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
    _migrate_posts_add_title(db)


def fetch_db_user(username):
    if not username:
        return None
    db = get_db()
    row = db.execute(
        "SELECT username FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    return row["username"] if row else None


# ---------------------------
# CSRF
# ---------------------------

def generate_csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def is_ajax():
    # fetchでもXMLHttpRequestでもまとめて扱う
    return request.headers.get("X-Requested-With") is not None or request.accept_mimetypes.best == "application/json"


def validate_csrf():
    form_token = request.form.get("csrf_token", "")
    header_token = (
        request.headers.get("X-CSRFToken")
        or request.headers.get("X-CSRF-Token")
        or request.headers.get("X-CSRF")
        or ""
    )
    token = form_token or header_token

    session_token = session.get("_csrf_token")
    if not token or not session_token or token != session_token:
        abort(400, description="Invalid CSRF token")


app.jinja_env.globals["csrf_token"] = generate_csrf_token


# ---------------------------
# 認証関連
# ---------------------------

@app.before_request
def load_logged_in_user():
    """
    ★重要：ここで必ず init_db() してテーブル未作成でも落ちないようにする
    """
    init_db()

    # 言語：?lang=ja/en が付いていれば反映
    qlang = request.args.get("lang")
    if qlang in SUPPORTED_LANGS:
        session["lang"] = qlang

    username = session.get("user")
    real_user = fetch_db_user(username)

    # セッションに user がいても、DBにいなければ無効化
    if real_user is None and "user" in session:
        session.pop("user", None)

    g.user = real_user  # None か DBに存在するusername


def login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def login_required_api(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            # ★APIは必ず「ログインへ誘導」情報も返す（JSで扱える）
            return jsonify({
                "ok": False,
                "reason": "auth",
                "redirect": url_for("login", next=request.path),
            }), 401
        return view(*args, **kwargs)
    return wrapped


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
    db = get_db()

    posts = db.execute(
        """
        SELECT id, filename, user, title, votes, created_at
        FROM posts
        ORDER BY votes DESC, created_at DESC
        """
    ).fetchall()

    voted_ids = set()
    if g.user:
        rows = db.execute(
            "SELECT post_id FROM votes WHERE user = ?",
            (g.user,),
        ).fetchall()
        voted_ids = {r["post_id"] for r in rows}

    return render_template(
        "home.html",
        posts=posts,
        user=g.user,
        is_logged_in=bool(g.user),
        voted_ids=voted_ids,
    )


@app.route("/login", methods=["GET", "POST"])
def login():
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
            return render_template("login.html", error=t("login_invalid"))

        session["user"] = row["username"]
        return redirect(_safe_next_url(next_url))

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        validate_csrf()
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        password2 = request.form.get("password2") or ""

        if not username or not password:
            return render_template("register.html", error=t("reg_need_userpass"))

        if password2 and password2 != password:
            return render_template("register.html", error=t("reg_pw_mismatch"))

        db = get_db()
        exists = db.execute(
            "SELECT 1 FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        if exists:
            return render_template("register.html", error=t("reg_taken"))

        db.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
            (username, generate_password_hash(password), datetime.utcnow().isoformat()),
        )
        db.commit()
        session["user"] = username
        return redirect(url_for("index"))

    return render_template("register.html")


@app.route("/logout", methods=["POST"])
def logout():
    validate_csrf()
    session.pop("user", None)
    return redirect(url_for("index"))


@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    if request.method == "POST":
        validate_csrf()
        if "photo" not in request.files:
            return render_template("upload.html", error=t("up_no_file"))

        file = request.files["photo"]
        if file.filename == "":
            return render_template("upload.html", error=t("up_empty_name"))

        if not allowed_file(file.filename):
            return render_template("upload.html", error=t("up_bad_type"))

        title = (request.form.get("title") or "").strip()
        if len(title) > 80:
            title = title[:80]

        filename = secure_filename(file.filename)
        random_prefix = secrets.token_hex(8)
        final_name = f"{random_prefix}_{filename}"
        save_path = UPLOAD_DIR / final_name
        file.save(save_path)

        db = get_db()
        db.execute(
            "INSERT INTO posts (filename, user, title, created_at, votes) VALUES (?, ?, ?, ?, 0)",
            (final_name, g.user, title or None, datetime.utcnow().isoformat()),
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
    validate_csrf()
    db = get_db()

    exists = db.execute(
        "SELECT 1 FROM votes WHERE user = ? AND post_id = ?",
        (g.user, post_id),
    ).fetchone()

    if exists:
        cur_votes = db.execute("SELECT votes FROM posts WHERE id = ?", (post_id,)).fetchone()["votes"]
        return jsonify({"ok": True, "post_id": post_id, "votes": cur_votes, "voted": True})

    db.execute(
        "INSERT INTO votes (user, post_id, created_at) VALUES (?, ?, ?)",
        (g.user, post_id, datetime.utcnow().isoformat()),
    )
    db.execute("UPDATE posts SET votes = votes + 1 WHERE id = ?", (post_id,))
    db.commit()

    new_votes = db.execute("SELECT votes FROM posts WHERE id = ?", (post_id,)).fetchone()["votes"]
    return jsonify({"ok": True, "post_id": post_id, "votes": new_votes, "voted": True})


@app.route("/unvote/<int:post_id>", methods=["POST"])
@login_required_api
def unvote(post_id):
    validate_csrf()
    db = get_db()

    exists = db.execute(
        "SELECT 1 FROM votes WHERE user = ? AND post_id = ?",
        (g.user, post_id),
    ).fetchone()

    if not exists:
        cur_votes = db.execute("SELECT votes FROM posts WHERE id = ?", (post_id,)).fetchone()["votes"]
        return jsonify({"ok": True, "post_id": post_id, "votes": cur_votes, "voted": False})

    db.execute("DELETE FROM votes WHERE user = ? AND post_id = ?", (g.user, post_id))
    db.execute("UPDATE posts SET votes = MAX(votes - 1, 0) WHERE id = ?", (post_id,))
    db.commit()

    new_votes = db.execute("SELECT votes FROM posts WHERE id = ?", (post_id,)).fetchone()["votes"]
    return jsonify({"ok": True, "post_id": post_id, "votes": new_votes, "voted": False})


# ---------------------------
# i18n error strings
# ---------------------------

TRANSLATIONS["ja"].update({
    "login_invalid": "ユーザー名またはパスワードが違います。",
    "reg_need_userpass": "ユーザー名とパスワードを入力してください。",
    "reg_pw_mismatch": "パスワード（確認）が一致しません。",
    "reg_taken": "このユーザー名は既に使われています。",
    "up_no_file": "ファイルが選択されていません。",
    "up_empty_name": "ファイル名が空です。",
    "up_bad_type": "対応していないファイル形式です。（png/jpg/jpeg/webp）",
})
TRANSLATIONS["en"].update({
    "login_invalid": "Invalid username or password.",
    "reg_need_userpass": "Please enter a username and password.",
    "reg_pw_mismatch": "Passwords do not match.",
    "reg_taken": "That username is already taken.",
    "up_no_file": "No file selected.",
    "up_empty_name": "Filename is empty.",
    "up_bad_type": "Unsupported file type. (png/jpg/jpeg/webp)",
})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=DEBUG)
