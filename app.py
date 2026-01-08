import os
import sqlite3
import json
import tempfile
import shutil
from datetime import datetime
from functools import wraps

from flask import (
    Flask, request, session, redirect, url_for, render_template,
    flash, send_from_directory, abort, jsonify
)
import requests
try:
    import markdown
except Exception:
    markdown = None

# config from env
GITHUB_CLIENT_ID = os.environ.get("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET")
SECRET_KEY = os.environ.get("FLASK_SECRET")

if not GITHUB_CLIENT_ID:
    raise RuntimeError("GITHUB_CLIENT_ID is not set in the environment.")
if not GITHUB_CLIENT_SECRET:
    raise RuntimeError("GITHUB_CLIENT_SECRET is not set in the environment.")
if not SECRET_KEY:
    raise RuntimeError("FLASK_SECRET is not set in the environment.")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PKGS_DIR = os.path.join(BASE_DIR, "pkgs")
DB_PATH = os.path.join(BASE_DIR, "db/db.sqlite3")

app = Flask(__name__)
app.secret_key = SECRET_KEY

# ---------- minimal sqlite helper ----------
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    # users table unchanged
    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        github_id INTEGER UNIQUE,
        login TEXT,
        name TEXT
    )""")
    # packages table now stores every (package name, version) as a row
    c.execute("""
    CREATE TABLE IF NOT EXISTS packages (
        id INTEGER PRIMARY KEY,
        name TEXT,
        version TEXT,
        owner_id INTEGER,
        filename TEXT,
        uploaded_at TEXT,
        UNIQUE(name, version),
        FOREIGN KEY(owner_id) REFERENCES users(id)
    )""")
    conn.commit()
    conn.close()

init_db()

# ---------- auth helpers ----------
def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapped

def current_user():
    if "user_id" not in session:
        return None
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    conn.close()
    return user

# ---------- GitHub OAuth ----------
@app.route("/login")
def login():
    state = os.urandom(16).hex()
    session["oauth_state"] = state
    redirect_uri = url_for('callback', _external=True)
    auth_url = ("https://github.com/login/oauth/authorize"
                f"?client_id={GITHUB_CLIENT_ID}&state={state}&redirect_uri={redirect_uri}&scope=read:user")
    return redirect(auth_url)

@app.route("/callback")
def callback():
    code = request.args.get("code")
    state = request.args.get("state")
    if not code or state != session.get("oauth_state"):
        return "OAuth failed (state mismatch)", 400
    # exchange code
    token_resp = requests.post("https://github.com/login/oauth/access_token", data={
        "client_id": GITHUB_CLIENT_ID,
        "client_secret": GITHUB_CLIENT_SECRET,
        "code": code
    }, headers={"Accept": "application/json"})
    token_json = token_resp.json()
    access_token = token_json.get("access_token")
    if not access_token:
        return "OAuth token error", 400
    # fetch user
    user_resp = requests.get("https://api.github.com/user", headers={
        "Authorization": f"token {access_token}",
        "Accept": "application/vnd.github.v3+json"
    })
    user_json = user_resp.json()
    github_id = user_json.get("id")
    login_name = user_json.get("login")
    real_name = user_json.get("name") or ""
    if not github_id:
        return "GitHub user fetch failed", 400
    # upsert into users
    conn = get_db()
    c = conn.cursor()
    existing = c.execute("SELECT * FROM users WHERE github_id = ?", (github_id,)).fetchone()
    if existing:
        c.execute("UPDATE users SET login=?, name=? WHERE github_id = ?", (login_name, real_name, github_id))
        user_id = existing["id"]
    else:
        c.execute("INSERT INTO users (github_id, login, name) VALUES (?, ?, ?)", (github_id, login_name, real_name))
        user_id = c.lastrowid
    conn.commit()
    conn.close()
    session["user_id"] = user_id
    session["github_login"] = login_name
    return redirect(url_for("index"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

# ---------- helpers ----------
def secure_package_path(pkg_name, version):
    # only allow alnum, - and _ for package, and limited chars for version
    safe_pkg = "".join(c for c in pkg_name if c.isalnum() or c in "-_").strip()
    safe_ver = "".join(c for c in version if c.isalnum() or c in ".-_").strip()
    if not safe_pkg or not safe_ver:
        raise ValueError("unsafe package or version")
    return os.path.join(PKGS_DIR, safe_pkg, safe_ver), safe_pkg, safe_ver

# ---------- pages ----------
@app.route("/")
def index():
    q = request.args.get("q", "").strip()
    conn = get_db()
    if q:
        # search package names
        rows = conn.execute(
            "SELECT p1.name, p1.version, p1.uploaded_at, u.login as owner_login "
            "FROM packages p1 "
            "JOIN (SELECT name, max(uploaded_at) as ma FROM packages WHERE name LIKE ? GROUP BY name) p2 "
            "ON p1.name=p2.name AND p1.uploaded_at=p2.ma "
            "LEFT JOIN users u ON p1.owner_id=u.id "
            "ORDER BY p1.name",
            (f"%{q}%",)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT p1.name, p1.version, p1.uploaded_at, u.login as owner_login "
            "FROM packages p1 "
            "JOIN (SELECT name, max(uploaded_at) as ma FROM packages GROUP BY name) p2 "
            "ON p1.name=p2.name AND p1.uploaded_at=p2.ma "
            "LEFT JOIN users u ON p1.owner_id=u.id "
            "ORDER BY p1.name LIMIT 50"
        ).fetchall()
    packages = [dict(r) for r in rows]
    conn.close()
    return render_template("index.html", packages=packages, q=q, user=current_user())

@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    conn = get_db()
    # For each package name owned by the user, show the latest version
    rows = conn.execute(
        "SELECT p1.* FROM packages p1 "
        "JOIN (SELECT name, max(uploaded_at) as ma FROM packages WHERE owner_id = ? GROUP BY name) p2 "
        "ON p1.name=p2.name AND p1.uploaded_at=p2.ma "
        "WHERE p1.owner_id = ? ORDER BY p1.name",
        (user["id"], user["id"])
    ).fetchall()
    conn.close()
    return render_template("dashboard.html", packages=rows, user=user)


@app.route("/delete_package/<name>", methods=["POST"])
@login_required
def delete_package(name):
    user = current_user()

    conn = get_db()
    c = conn.cursor()

    rows = c.execute(
        "SELECT DISTINCT owner_id FROM packages WHERE name = ?",
        (name,)
    ).fetchall()

    if not rows:
        conn.close()
        abort(404)

    # if any owner_id differs from current user -> forbidden
    owner_ids = {r[0] for r in rows}
    if owner_ids != {user["id"]}:
        conn.close()
        abort(403)

    # delete package rows
    c.execute("DELETE FROM packages WHERE name = ?", (name,))
    conn.commit()
    conn.close()

    # delete disk directory pkgs/<name>
    pkg_dir = os.path.join(PKGS_DIR, name)
    if os.path.exists(pkg_dir):
        shutil.rmtree(pkg_dir, ignore_errors=True)

    flash(f"包 {name} 已成功删除")
    return redirect(url_for("dashboard"))

@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    if request.method == "GET":
        return render_template("upload.html", user=current_user())

    files = request.files.getlist("files")
    tmpdir = None

    try:
        if not files:
            flash("没有上传文件")
            return redirect(url_for("upload"))

        # 1️⃣ 保存上传目录到临时目录
        tmpdir = tempfile.mkdtemp()
        for f in files:
            safe_rel = os.path.normpath(f.filename)
            if safe_rel.startswith(".."):
                continue
            dest = os.path.join(tmpdir, safe_rel)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            f.save(dest)

        # 2️⃣ 查找 package.json
        package_json_path = None
        for root, _, filenames in os.walk(tmpdir):
            if "package.json" in filenames:
                package_json_path = os.path.join(root, "package.json")
                break

        if not package_json_path:
            flash("上传目录中未找到 package.json")
            return redirect(url_for("upload"))

        with open(package_json_path, "r", encoding="utf-8") as f:
            pj = json.load(f)

        name = pj.get("name")
        version = pj.get("version")

        if not name or not version:
            flash("package.json 必须包含 name 和 version")
            return redirect(url_for("upload"))

        # 3️⃣ 包名安全检查
        safe_name = "".join(c for c in name if c.isalnum() or c in "-_")
        if safe_name != name:
            flash("包名只能包含字母数字、- 和 _")
            return redirect(url_for("upload"))

        conn = get_db()
        c = conn.cursor()

        # 4️⃣ 查询包是否已有相同 name & version
        exists = c.execute(
            "SELECT * FROM packages WHERE name = ? AND version = ?",
            (name, version)
        ).fetchone()

        if exists:
            conn.close()
            flash("该版本已存在")
            return redirect(url_for("upload"))

        # 5️⃣ 检查是否已有该包且不是你所有
        owner_row = c.execute("SELECT owner_id FROM packages WHERE name = ? LIMIT 1", (name,)).fetchone()
        user_id = session["user_id"]
        if owner_row and owner_row["owner_id"] != user_id:
            conn.close()
            flash("你不是该包的所有者，无法上传新版本")
            return redirect(url_for("upload"))

        # 6️⃣ 安全路径
        try:
            dest_dir, _, _ = secure_package_path(name, version)
        except ValueError:
            conn.close()
            flash("包名或版本不安全")
            return redirect(url_for("upload"))

        os.makedirs(dest_dir, exist_ok=True)

        # 7️⃣ 复制 package.json 所在目录内容
        pkg_base_dir = os.path.dirname(package_json_path)
        for item in os.listdir(pkg_base_dir):
            s = os.path.join(pkg_base_dir, item)
            d = os.path.join(dest_dir, item)
            if os.path.isdir(s):
                shutil.copytree(s, d)
            else:
                shutil.copy2(s, d)

        # 8️⃣ 写入 packages 表 (每个版本一行)
        uploaded_at = datetime.utcnow().isoformat() + "Z"
        c.execute(
            "INSERT INTO packages (name, version, owner_id, filename, uploaded_at) VALUES (?, ?, ?, ?, ?)",
            (name, version, user_id, "", uploaded_at)
        )

        conn.commit()
        conn.close()

        flash(f"上传成功：{name} {version}")
        return redirect(url_for("package_view", name=name))

    finally:
        if tmpdir and os.path.exists(tmpdir):
            shutil.rmtree(tmpdir, ignore_errors=True)


@app.route("/package/<name>")
def package_view(name):
    # show versions, readme, install command
    conn = get_db()
    pkg_rows = conn.execute("SELECT * FROM packages WHERE name = ? ORDER BY uploaded_at DESC", (name,)).fetchall()
    if not pkg_rows:
        conn.close()
        abort(404)
    conn.close()

    versions = [dict(r) for r in pkg_rows]

    # find latest README.md in pkgs
    readme_html = None
    latest_ver = None
    for v in versions:
        try:
            dest_dir, _, _ = secure_package_path(name, v["version"])
        except Exception:
            continue
        rd = os.path.join(dest_dir, "README.md")
        if os.path.exists(rd):
            with open(rd, "r", encoding="utf-8") as fh:
                txt = fh.read()
            if markdown:
                readme_html = markdown.markdown(txt)
            else:
                # fallback: basic preformatted
                readme_html = "<pre>" + (txt.replace("&", "&amp;").replace("<", "&lt;")) + "</pre>"
            latest_ver = v["version"]
            break
    return render_template("package.html", package=versions[0], versions=versions, readme_html=readme_html, latest_ver=latest_ver, user=current_user())


@app.route('/pkgs/<path:filename>')
def public_pkgs(filename):
    return send_from_directory(PKGS_DIR, filename)

# small API to list versions (could be used by micropython clients)
@app.route("/api/<name>/versions")
def api_versions(name):
    conn = get_db()
    rows = conn.execute("SELECT version, uploaded_at FROM packages WHERE name = ? ORDER BY uploaded_at DESC", (name,)).fetchall()
    conn.close()
    if not rows:
        return jsonify({"error": "not found"}), 404
    return jsonify([dict(r) for r in rows])

# ---------- simple error handlers ----------
@app.errorhandler(404)
def notfound(e):
    return render_template("404.html"), 404

if __name__ == "__main__":
    app.run(ssl_context=('/tls/cert.crt', '/tls/cert.key'), host="0.0.0.0", port=443)
