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
ALLOWED_EXTENSIONS = {"zip"}

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
    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        github_id INTEGER UNIQUE,
        login TEXT,
        name TEXT
    )""")
    c.execute("""
    CREATE TABLE IF NOT EXISTS packages (
        id INTEGER PRIMARY KEY,
        name TEXT UNIQUE,
        owner_id INTEGER,
        FOREIGN KEY(owner_id) REFERENCES users(id)
    )""")
    c.execute("""
    CREATE TABLE IF NOT EXISTS versions (
        id INTEGER PRIMARY KEY,
        package_id INTEGER,
        version TEXT,
        filename TEXT,
        uploaded_at TEXT,
        FOREIGN KEY(package_id) REFERENCES packages(id)
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
    # only allow alnum, - and _
    safe_pkg = "".join(c for c in pkg_name if c.isalnum() or c in "-_").strip()
    safe_ver = "".join(c for c in version if c.isalnum() or c in ".-_").strip()
    if not safe_pkg or not safe_ver:
        raise ValueError("unsafe package or version")
    return os.path.join(PKGS_DIR, safe_pkg, safe_ver), safe_pkg, safe_ver

def extract_zip_to_tmp(zipfile_path):
    import zipfile
    tmpdir = tempfile.mkdtemp()
    with zipfile.ZipFile(zipfile_path, 'r') as z:
        z.extractall(tmpdir)
    return tmpdir

# ---------- pages ----------
@app.route("/")
def index():
    q = request.args.get("q", "").strip()
    conn = get_db()
    if q:
        rows = conn.execute("SELECT * FROM packages WHERE name LIKE ? ORDER BY name", (f"%{q}%",)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM packages ORDER BY name LIMIT 50").fetchall()
    packages = [dict(r) for r in rows]
    conn.close()
    return render_template("index.html", packages=packages, q=q, user=current_user())

@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    conn = get_db()
    pkgs = conn.execute("SELECT * FROM packages WHERE owner_id = ? ORDER BY name", (user["id"],)).fetchall()
    conn.close()
    return render_template("dashboard.html", packages=pkgs, user=user)

@app.route("/delete_package/<name>", methods=["POST"])
@login_required
def delete_package(name):
    user = current_user()

    conn = get_db()
    c = conn.cursor()

    pkg = c.execute(
        "SELECT * FROM packages WHERE name=?",
        (name,)
    ).fetchone()

    if not pkg:
        conn.close()
        abort(404)

    # 权限验证：包 owner
    if not (pkg["owner_id"] == user["id"]):
        conn.close()
        abort(403)

    # 删除 versions 记录
    c.execute("DELETE FROM versions WHERE package_id = ?", (pkg["id"],))
    # 删除 package
    c.execute("DELETE FROM packages WHERE id = ?", (pkg["id"],))
    conn.commit()
    conn.close()

    # 删除磁盘目录 pkgs/<name>
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
    # POST: accept either a single zip or multiple files (webkitdirectory)
    files = request.files.getlist("files")
    zipfile = request.files.get("zipfile")
    # handle zip
    tmpdir = None
    try:
        if files and len(files) > 0:
            # save files preserving path info (some browsers provide subpaths in filename)
            tmpdir = tempfile.mkdtemp()
            for f in files:
                # f.filename may include directories like "pkg/package.json" when using webkitdirectory
                safe_rel = os.path.normpath(f.filename)
                if safe_rel.startswith(".."):
                    continue
                dest = os.path.join(tmpdir, safe_rel)
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                f.save(dest)
        else:
            flash("没有上传文件")
            return redirect(url_for("upload"))

        # find package.json
        package_json_path = None
        for root, dirs, filenames in os.walk(tmpdir):
            if "package.json" in filenames:
                package_json_path = os.path.join(root, "package.json")
                break
        if not package_json_path:
            flash("上传包内未找到 package.json")
            return redirect(url_for("upload"))
        with open(package_json_path, "r", encoding="utf-8") as fh:
            pj = json.load(fh)
        name = pj.get("name")
        version = pj.get("version")
        if not name or not version:
            flash("package.json 必须包含 name 与 version 字段")
            return redirect(url_for("upload"))

        # basic name sanity
        safe = "".join(c for c in name if c.isalnum() or c in "-_").strip()
        if safe != name:
            flash("包名只能包含字母数字、- 和 _")
            return redirect(url_for("upload"))
        conn = get_db()
        c = conn.cursor()
        existing = c.execute("SELECT * FROM packages WHERE name = ?", (name,)).fetchone()
        if existing:
            flash("包已存在")
            conn.close()
            return redirect(url_for("upload"))
        c.execute("INSERT INTO packages (name, owner_id) VALUES (?, ?)", (name, session["user_id"]))
        conn.commit()
        conn.close()

        # store to pkgs/<name>/<version> (ensure package exists in DB)
        conn = get_db()
        c = conn.cursor()
        pkg = c.execute("SELECT * FROM packages WHERE name = ?", (name,)).fetchone()
        if not pkg:
            # optionally create package automatically and assign to uploader
            c.execute("INSERT OR IGNORE INTO packages (name, owner_id) VALUES (?, ?)", (name, session["user_id"]))
            conn.commit()
            pkg = c.execute("SELECT * FROM packages WHERE name = ?", (name,)).fetchone()
        package_id = pkg["id"]

        # check version uniqueness
        exists = c.execute("SELECT * FROM versions WHERE package_id = ? AND version = ?", (package_id, version)).fetchone()
        if exists:
            flash("该版本已存在")
            conn.close()
            return redirect(url_for("upload"))

        # safe path and copy
        try:
            dest_dir, safe_pkg, safe_ver = secure_package_path(name, version)
        except ValueError:
            flash("包名或版本不安全")
            conn.close()
            return redirect(url_for("upload"))
        os.makedirs(dest_dir, exist_ok=True)
        # copy files from tmpdir root to dest_dir (preserve inner structure)
        # if package.json located in a subfolder, want to copy only that folder contents.
        # we will copy the directory that contains package.json (so nested zips are handled).
        pkg_base_dir = os.path.dirname(package_json_path)
        for item in os.listdir(pkg_base_dir):
            s = os.path.join(pkg_base_dir, item)
            d = os.path.join(dest_dir, item)
            if os.path.isdir(s):
                shutil.copytree(s, d)
            else:
                shutil.copy2(s, d)
        # ensure package.json exists at dest
        if not os.path.exists(os.path.join(dest_dir, "package.json")):
            shutil.copy2(package_json_path, os.path.join(dest_dir, "package.json"))

        # record version
        uploaded_at = datetime.utcnow().isoformat() + "Z"
        c.execute("INSERT INTO versions (package_id, version, filename, uploaded_at) VALUES (?, ?, ?, ?)",
                  (package_id, version, "", uploaded_at))
        conn.commit()
        conn.close()
        flash(f"上传成功：{name} {version}")
        return redirect(url_for("package_view", name=safe_pkg))
    finally:
        if tmpdir and os.path.exists(tmpdir):
            shutil.rmtree(tmpdir, ignore_errors=True)


@app.route("/package/<name>")
def package_view(name):
    # show versions, readme, install command
    conn = get_db()
    pkg = conn.execute("SELECT * FROM packages WHERE name = ?", (name,)).fetchone()
    if not pkg:
        conn.close()
        abort(404)
    versions = conn.execute("SELECT * FROM versions WHERE package_id = ? ORDER BY uploaded_at DESC", (pkg["id"],)).fetchall()
    conn.close()
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
    return render_template("package.html", package=pkg, versions=versions, readme_html=readme_html, latest_ver=latest_ver, user=current_user())


@app.route('/pkgs/<path:filename>')
def public_pkgs(filename):
    return send_from_directory(PKGS_DIR, filename)

# small API to list versions (could be used by micropython clients)
@app.route("/api/<name>/versions")
def api_versions(name):
    conn = get_db()
    pkg = conn.execute("SELECT * FROM packages WHERE name = ?", (name,)).fetchone()
    if not pkg:
        conn.close()
        return jsonify({"error": "not found"}), 404
    versions = conn.execute("SELECT version, uploaded_at FROM versions WHERE package_id = ? ORDER BY uploaded_at DESC", (pkg["id"],)).fetchall()
    conn.close()
    return jsonify([dict(v) for v in versions])

# ---------- simple error handlers ----------
@app.errorhandler(404)
def notfound(e):
    return render_template("404.html"), 404

if __name__ == "__main__":
    app.run(ssl_context=('/tls/cert.crt', '/tls/cert.key'), host="0.0.0.0", port=80)
