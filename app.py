import os
import stat
import shutil
import zipfile
import tempfile

from pathlib import Path
from functools import wraps, lru_cache
from datetime import datetime

import subprocess

import uuid
import json
import sqlite3

import requests
import markdown

from flask import Flask, Response, render_template, request, redirect, url_for, session, flash, send_from_directory, abort, jsonify, g
from flask_babel import Babel, gettext as _

# 配置
GITHUB_CLIENT_ID = os.getenv('GITHUB_CLIENT_ID')
GITHUB_CLIENT_SECRET = os.getenv('GITHUB_CLIENT_SECRET')
FLASK_SECRET = os.getenv('FLASK_SECRET')
if not GITHUB_CLIENT_ID:
    raise RuntimeError("GITHUB_CLIENT_ID is not set in the environment.")
if not GITHUB_CLIENT_SECRET:
    raise RuntimeError("GITHUB_CLIENT_SECRET is not set in the environment.")
if not FLASK_SECRET:
    raise RuntimeError("FLASK_SECRET is not set in the environment.")

# 初始化应用
app = Flask(__name__)

app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024

app.config['BABEL_DEFAULT_LOCALE'] = 'en'
app.config['BABEL_SUPPORTED_LOCALES'] = ['zh', 'en']
app.config['BABEL_TRANSLATION_DIRECTORIES'] = 'translations'

app.secret_key = FLASK_SECRET

# ---------- 多语言支持 ----------
def alt_url(lang, external=False):
    args = dict(request.view_args or {})
    args['lang'] = lang
    return url_for(request.endpoint, _external=external, **args)
app.jinja_env.globals['alt_url'] = alt_url

@app.url_value_preprocessor
def pull_lang(endpoint, values):
    if values is None:
        return
    lang = values.pop('lang', None)
    if lang in app.config['BABEL_SUPPORTED_LOCALES']:
        g.lang = lang
    else:
        g.lang = 'en'

@app.url_defaults
def add_lang(endpoint, values):
    if 'lang' in values or not hasattr(g, 'lang'):
        return
    values['lang'] = g.lang

# 初始化Babel
def get_locale():
    return getattr(g, 'lang', 'en')
babel = Babel(app, locale_selector=get_locale)

# ---------- 数据库 ----------
def init_db():
    """初始化数据库"""
    conn = sqlite3.connect('db/db.sqlite3')
    c = conn.cursor()
    
    # 创建用户表
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            github_id INTEGER UNIQUE NOT NULL,
            login TEXT NOT NULL,
            name TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # 创建包表
    c.execute('''
        CREATE TABLE IF NOT EXISTS packages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            version TEXT NOT NULL,
            owner_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (owner_id) REFERENCES users (id),
            UNIQUE(name, version)
        )
    ''')
    
    conn.commit()
    conn.close()

init_db()

def get_db():
    """获取数据库连接"""
    conn = sqlite3.connect('db/db.sqlite3')
    conn.row_factory = sqlite3.Row
    return conn

# ---------- 辅助函数 ----------
def login_required(f):
    """登录装饰器"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash(_('请先登录'), 'error')
            return redirect(url_for('login', lang=g.lang))
        return f(*args, **kwargs)
    return decorated_function

def get_current_user():
    """获取当前用户信息"""
    if 'user_id' not in session:
        return None
    
    conn = get_db()
    user = conn.execute(
        'SELECT * FROM users WHERE id = ?', 
        (session['user_id'],)
    ).fetchone()
    conn.close()
    
    return user

@lru_cache(maxsize=1024)
def get_package_json(folder: Path, mtime: float) -> dict | None:
    path = folder / "package.json"
    if not path.is_file():
        return None
    
    data = json.loads(path.read_text("utf-8"))
    if "name" in data and "version" in data:
        return data
    else:
        return None

def get_package_files(package_name, version):
    """获取指定版本包的文件列表"""
    from pathlib import Path
    
    # 版本目录
    package_dir = Path('pkgs') / package_name / version
    
    if not package_dir.exists():
        return []
    
    files = []
    try:
        for file_path in package_dir.rglob('*'):
            if file_path.is_file():
                # 获取相对路径
                rel_path = file_path.relative_to(package_dir)
                # 获取文件大小
                size = file_path.stat().st_size
                # 格式化文件大小
                if size < 1024:
                    size_str = f"{size}B"
                elif size < 1024 * 1024:
                    size_str = f"{size/1024:.1f}KB"
                else:
                    size_str = f"{size/(1024*1024):.1f}MB"
                
                files.append({
                    'name': str(rel_path),
                    'size': size_str,
                    'is_package_json': rel_path.name == 'package.json',
                    'is_readme': rel_path.name.lower() in ['readme.md', 'readme.txt', 'readme'],
                    'is_main': rel_path.name.lower() in ['main.py', '__init__.py']
                })
        
        # 按文件名排序
        files.sort(key=lambda x: x['name'])
        return files
    except Exception as e:
        app.logger.error(f'获取文件列表失败: {str(e)}')
        return []

def get_package_versions(package_name):
    """获取包的全部版本"""
    conn = get_db()

    rows = conn.execute(
        '''
        SELECT version
        FROM packages
        WHERE name = ?
        ORDER BY id DESC
        ''',
        (package_name,)
    ).fetchall()

    conn.close()

    return [row['version'] for row in rows]

def unzip(zip_path, dest):
    """解压zip文件到目标目录"""
    MAX_FILES = 2000
    MAX_UNZIP_SIZE = 10 * 1024 * 1024

    with zipfile.ZipFile(zip_path) as z:
        infos = z.infolist()
        if len(infos) > MAX_FILES:
            raise ValueError("too many files")

        total = 0
        for info in infos:
            path = Path(info.filename)

            # 防路径攻击
            if ".." in path.parts or path.is_absolute():
                raise ValueError("invalid path")
            # 防 symlink
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise ValueError("symlink not allowed")
            # 防 zip bomb
            total += info.file_size
            if total > MAX_UNZIP_SIZE:
                raise ValueError("zip too large")

            target = dest / path
            target.parent.mkdir(parents=True, exist_ok=True)
            if info.is_dir():
                target.mkdir(exist_ok=True)
                continue
            with z.open(info) as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst)

# ---------- 根路由 ----------
@app.route('/')
def root():
    return redirect('/en/')

@app.route('/<lang>/', strict_slashes=False)
def index():
    """首页"""
    conn = get_db()
    
    # 获取最新的包（按创建时间排序，每个包只取最新版本）
    recent_packages = conn.execute('''
        SELECT p.*, u.login AS owner_name
        FROM packages p
        JOIN users u ON p.owner_id = u.id
        WHERE p.id = (
            SELECT MAX(id)
            FROM packages p2
            WHERE p2.name = p.name
        )
        ORDER BY p.id DESC
        LIMIT 10
    ''').fetchall()
    
    # 获取包总数（按名称去重）
    total_packages = conn.execute('SELECT COUNT(DISTINCT name) as count FROM packages').fetchone()['count']
    
    conn.close()

    for i, pkg in enumerate(recent_packages):
        pkg = dict(pkg)
        path = Path("pkgs") / pkg["name"] / pkg["version"]
        info = get_package_json(path, path.stat().st_mtime)
        if info:
            pkg.update(info)
        recent_packages[i] = pkg
    return render_template('index.html', 
                         recent_packages=recent_packages,
                         total_packages=total_packages,
                         user=get_current_user())
# ---------- 用户管理 ----------
@app.route('/<lang>/login', strict_slashes=False)
def login():
    """开发模式：直接登录 test 用户"""
    # conn = get_db()
    # conn.execute(
    #     'INSERT OR IGNORE INTO users (github_id, login, name) VALUES (0,"test","test")'
    # )
    # user = conn.execute(
    #     'SELECT id FROM users WHERE github_id = 0'
    # ).fetchone()

    # conn.commit()
    # conn.close()

    # session['user_id'] = user["id"]
    # session['github_login'] = "test"

    # flash(_('欢迎回来，{}!').format("test"), 'success')
    # return redirect(url_for('dashboard', lang=g.lang))

    """GitHub OAuth 登录"""
    state = os.urandom(16).hex()
    session['oauth_state'] = state
    redirect_uri = url_for('callback', _external=True)
    
    auth_url = (f"https://github.com/login/oauth/authorize"
                f"?client_id={GITHUB_CLIENT_ID}"
                f"&state={state}"
                f"&redirect_uri={redirect_uri}"
                f"&scope=read:user")
    
    return redirect(auth_url)

@app.route('/callback', strict_slashes=False)
def callback():
    """GitHub OAuth 回调"""
    code = request.args.get('code')
    state = request.args.get('state')
    
    if not code or state != session.get('oauth_state'):
        flash(_('OAuth 认证失败 (state mismatch)'), 'error')
        return redirect(url_for('index', lang=g.lang))
    
    # 交换 code 获取 access_token
    token_resp = requests.post(
        'https://github.com/login/oauth/access_token',
        data={
            'client_id': GITHUB_CLIENT_ID,
            'client_secret': GITHUB_CLIENT_SECRET,
            'code': code
        },
        headers={'Accept': 'application/json'},
        timeout=30
    )
    
    token_json = token_resp.json()
    access_token = token_json.get('access_token')
    
    if not access_token:
        flash(_('OAuth token 错误'), 'error')
        return redirect(url_for('index', lang=g.lang))
    
    # 获取用户信息
    user_resp = requests.get(
        'https://api.github.com/user',
        headers={
            'Authorization': f'token {access_token}',
            'Accept': 'application/vnd.github.v3+json'
        },
        timeout=30
    )
    
    user_json = user_resp.json()
    github_id = user_json.get('id')
    login_name = user_json.get('login')
    real_name = user_json.get('name') or login_name
    
    if not github_id:
        flash(_('GitHub 用户信息获取失败'), 'error')
        return redirect(url_for('index', lang=g.lang))
    
    # 插入或更新用户
    conn = get_db()
    existing = conn.execute(
        'SELECT * FROM users WHERE github_id = ?', 
        (github_id,)
    ).fetchone()
    
    if existing:
        conn.execute(
            'UPDATE users SET login = ?, name = ? WHERE github_id = ?',
            (login_name, real_name, github_id)
        )
        user_id = existing['id']
    else:
        cursor = conn.execute(
            'INSERT INTO users (github_id, login, name) VALUES (?, ?, ?)',
            (github_id, login_name, real_name)
        )
        user_id = cursor.lastrowid
    
    conn.commit()
    conn.close()
    
    # 保存会话
    session['user_id'] = user_id
    session['github_login'] = login_name
    
    flash(_('欢迎回来，{}!').format(login_name), 'success')
    return redirect(url_for('dashboard', lang=g.lang))

@app.route('/<lang>/logout', strict_slashes=False)
def logout():
    """退出登录"""
    session.clear()
    flash(_('已成功退出登录'), 'success')
    return redirect(url_for('index', lang=g.lang))

@app.route('/<lang>/dashboard', strict_slashes=False)
@login_required
def dashboard():
    """用户仪表板"""
    user = get_current_user()
    
    conn = get_db()
    user_packages = conn.execute('''
        SELECT p.*
        FROM packages p
        JOIN (
            SELECT name, MAX(id) AS max_id
            FROM packages
            WHERE owner_id = ?
            GROUP BY name
        ) latest
        ON p.id = latest.max_id
        ORDER BY p.id DESC
    ''', (user['id'],)).fetchall()
    
    conn.close()
    
    for i, pkg in enumerate(user_packages):
        pkg = dict(pkg)
        path = Path("pkgs") / pkg["name"] / pkg["version"]
        info = get_package_json(path, path.stat().st_mtime)
        if info:
            pkg.update(info)
        user_packages[i] = pkg

    return render_template('dashboard.html', 
                         user=user,
                         packages=user_packages)

# ---------- 包提交 ----------
@app.route('/<lang>/submit', methods=['POST'], strict_slashes=False)
@login_required
def submit():
    user = get_current_user()
    
    git_url = request.form.get('git_url')
    git_branch = request.form.get('git_branch') or 'main'
    git_paths = request.form.get('git_paths', '').split(',')
    git_paths = [p.strip() for p in git_paths if p.strip()]
    
    if not git_url:
        flash(_('Git URL不能为空'), 'error')
        return redirect(url_for('upload', lang=g.lang))

    temp_dir = Path(tempfile.gettempdir()) / str(uuid.uuid4())
    temp_dir.mkdir(parents=True)
    
    submitted = []   # 成功提交的包列表
    errors = []      # 提交失败信息列表
    
    try:
        # 克隆指定分支到临时目录
        subprocess.run(
            ['git', '-c', 'core.symlinks=false', 'clone', '--depth', '1', '--branch', git_branch, git_url, str(temp_dir)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        # 如果指定了子路径，只保留这些路径
        working_dirs = []
        if git_paths:
            filtered_dir = temp_dir / "extract"
            filtered_dir.mkdir()
            for path in git_paths:
                src = temp_dir / path.lstrip('/')
                if src.exists():
                    dest = filtered_dir / path.lstrip('/')
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    if src.is_dir():
                        shutil.copytree(src, dest)
                    else:
                        shutil.copy2(src, dest)
            working_dirs = [d for d in filtered_dir.iterdir() if d.is_dir()]
        else:
            working_dirs = [temp_dir]

        # 遍历所有目录，查找 package.json
        for folder in working_dirs:
            for subfolder in folder.rglob('*'):
                if subfolder.is_dir():
                    info = get_package_json(subfolder, subfolder.stat().st_mtime)
                    if not info:
                        continue

                    name = info['name']
                    version = info['version']

                    # 检查数据库是否已存在
                    conn = get_db()
                    exists = conn.execute(
                        'SELECT 1 FROM packages WHERE name=? AND version=?',
                        (name, version)
                    ).fetchone()
                    if exists:
                        errors.append(f"{name} {version} 已存在")
                        conn.close()
                        continue

                    conn.execute(
                        'INSERT INTO packages (name, version, owner_id) VALUES (?, ?, ?)',
                        (name, version, user['id'])
                    )
                    conn.commit()
                    conn.close()

                    # 限制包大小
                    MAX_SIZE = 10 * 1024 * 1024
                    total_size = sum(f.stat().st_size for f in subfolder.rglob('*') if f.is_file())
                    if total_size > MAX_SIZE:
                        errors.append(f"{name} {version} 超过大小限制")
                        continue

                    # 移动到 pkgs 目录
                    target_dir = Path('pkgs') / name / version
                    target_dir.parent.mkdir(parents=True, exist_ok=True)
                    shutil.move(str(subfolder), str(target_dir))

                    submitted.append(f"{name} {version} 提交成功")

        # 汇总提示信息
        for msg in submitted:
            flash(_(msg), 'success')
        for msg in errors:
            flash(_(msg), 'error')

        return redirect(url_for('dashboard', lang=g.lang))

    except subprocess.CalledProcessError as e:
        app.logger.error(f'Git clone error: {e.stderr.decode()}')
        flash(_('拉取仓库失败: %(msg)s', msg=e.stderr.decode()), 'error')
        return redirect(url_for('upload', lang=g.lang))
    except Exception as e:
        app.logger.error(f'Submit error: {str(e)}')
        flash(_('提交失败: %(msg)s', msg=str(e)), 'error')
        return redirect(url_for('upload', lang=g.lang))
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

@app.route('/<lang>/upload', methods=['GET', 'POST'], strict_slashes=False)
@login_required
def upload():
    """上传包"""
    if request.method == 'GET':
        return render_template('upload.html', user=get_current_user())

    user = get_current_user()
    files = request.files.getlist('files')

    if not files:
        flash(_('没有选择文件'), 'error')
        return redirect(request.url)

    for file in files:
        temp_dir = Path(tempfile.gettempdir()) / str(uuid.uuid4())
        temp_dir.mkdir()

        try:
            zip_path = temp_dir / "pkg.zip"
            file.save(zip_path)

            extract_dir = temp_dir / "extract"
            extract_dir.mkdir()

            unzip(zip_path, extract_dir)

            info = get_package_json(extract_dir, extract_dir.stat().st_mtime)

            if not info:
                flash(_('%(name)s 缺少package.json', name=file.filename), 'error')
                continue

            name = info["name"]
            version = info["version"]

            conn = get_db()

            exists = conn.execute(
                'SELECT 1 FROM packages WHERE name=? AND version=?',
                (name, version)
            ).fetchone()

            if exists:
                flash(_('%(name)s %(version)s 已存在', name=name, version=version), 'error')
                conn.close()
                continue

            conn.execute(
                'INSERT INTO packages (name, version, owner_id) VALUES (?, ?, ?)',
                (name, version, user['id'])
            )

            conn.commit()
            conn.close()

            target = Path("pkgs") / name / version
            target.parent.mkdir(parents=True, exist_ok=True)

            shutil.move(str(extract_dir), str(target))

            flash(_('%(name)s %(version)s 上传成功', name=name, version=version), 'success')

        except Exception as e:
            app.logger.error(f"upload error: {e}")
            flash(_('%(name)s 上传失败', name=file.filename), 'error')
        finally:
            # 清理临时目录
            shutil.rmtree(temp_dir, ignore_errors=True)
    return redirect(url_for('dashboard', lang=g.lang))

# ---------- 包索引 ----------
@app.route('/packages.json')
def packages_json():
    conn = get_db()

    rows = conn.execute('''
        SELECT name, version
        FROM packages p
        WHERE id = (
            SELECT MAX(id)
            FROM packages p2
            WHERE p2.name = p.name
        )
        ORDER BY name ASC
    ''').fetchall()

    conn.close()

    response = jsonify({
            "packages": [
                {
                    "name": row["name"],
                    "version": row["version"]
                }
                for row in rows
            ]
        })
    response.headers['Cache-Control'] = 'public, max-age=300'
    return response

@app.route('/<lang>/packages')
def packages():
    conn = get_db()

    all_packages = conn.execute('''
        SELECT p.*, u.login AS owner_name
        FROM packages p
        JOIN users u ON p.owner_id = u.id
        WHERE p.id = (
            SELECT MAX(id)
            FROM packages p2
            WHERE p2.name = p.name
        )
        ORDER BY p.name ASC
    ''').fetchall()

    conn.close()

    for i, row in enumerate(all_packages):
        pkg = dict(row)
        path = Path("pkgs") / pkg["name"] / pkg["version"]
        info = get_package_json(path, path.stat().st_mtime)
        if info:
            pkg.update(info)
        all_packages[i] = pkg

    return render_template(
        'packages.html',
        packages=all_packages,
        user=get_current_user()
    )

# ---------- 包管理 ----------
@app.route('/<lang>/pkgs/<name>', strict_slashes=False)
@app.route('/<lang>/pkgs/<name>/<version>', strict_slashes=False)
def package_detail(name, version=None):
    """包详情页面"""
    conn = get_db()
    
    # 获取包的所有版本信息
    package_versions = conn.execute('''
        SELECT p.*, u.login AS owner_name
        FROM packages p
        JOIN users u ON p.owner_id = u.id
        WHERE p.name = ?
        ORDER BY p.id DESC
    ''', (name,)).fetchall()
    
    if not package_versions:
        abort(404)
    
    # 如果没有指定版本，使用最新版本
    if not version:
        version = package_versions[0]['version']
    
    # 获取指定版本的详细信息
    current_package = None
    for pkg in package_versions:
        if pkg['version'] == version:
            current_package = dict(pkg)
            path = Path("pkgs") / name / version
            info = get_package_json(path, path.stat().st_mtime)
            if info:
                current_package.update(info)
            break
    
    if not current_package:
        abort(404)
    
    conn.close()
    
    # 获取README内容并渲染
    readme_path = Path('pkgs') / name / version / 'README.md'
    readme_content = None
    if readme_path.exists():
        with open(readme_path, 'r', encoding='utf-8') as f:
            readme_content = markdown.markdown(f.read(), extensions=["extra", "codehilite", "fenced_code", "tables", "toc"], output_format="html5")
    
    # 获取该版本的文件列表
    files = get_package_files(name, version)
    
    return render_template('package.html',
                         package_name=name,
                         current_version=version,
                         current_package=current_package,
                         package_versions=package_versions,
                         readme_content=readme_content,
                         files=files,
                         user=get_current_user())

@app.route('/<lang>/pkgs/<name>/<version>/delete', methods=['POST'], strict_slashes=False)
@login_required
def delete_package_version(name, version):
    """删除特定版本的包"""
    user = get_current_user()
    
    conn = get_db()
    
    # 检查包版本是否存在且用户是否有权限
    package = conn.execute(
        'SELECT * FROM packages WHERE name = ? AND version = ? AND owner_id = ?',
        (name, version, user['id'])
    ).fetchone()
    
    if not package:
        flash(_('包版本不存在或没有删除权限'), 'error')
        return redirect(url_for('package_detail', name=name))
    
    # 删除文件系统中的版本目录
    version_dir = Path('pkgs') / name / version
    if version_dir.exists():
        shutil.rmtree(str(version_dir))
    
    # 删除数据库中的版本记录
    conn.execute(
        'DELETE FROM packages WHERE name = ? AND version = ?',
        (name, version)
    )
    
    # 检查是否还有其他版本
    remaining_versions = conn.execute(
        'SELECT COUNT(*) as count FROM packages WHERE name = ?',
        (name,)
    ).fetchone()['count']
    
    conn.commit()
    conn.close()
    
    if remaining_versions == 0:
        # 如果没有其他版本，删除整个包目录
        package_dir = Path('pkgs') / name
        if package_dir.exists():
            shutil.rmtree(str(package_dir))
        flash(_('包 {}的所有版本已删除').format(name), 'success')
        return redirect(url_for('dashboard', lang=g.lang))
    else:
        flash(_('包 {} 版本 {} 已删除').format(name, version), 'success')
        # 重定向到最新版本
        return redirect(url_for('package_detail', name=name, version=get_package_versions(name)[0]))

@app.route('/<lang>/pkgs/<name>/<version>/download', strict_slashes=False)
def download_package(name, version):
    """下载指定版本的包"""
    package_dir = Path('pkgs') / name / version
    
    if not package_dir.exists():
        abort(404)
    
    # 创建临时zip文件
    import zipfile
    import tempfile
    
    # 创建临时文件
    temp_zip = tempfile.NamedTemporaryFile(delete=False, suffix='.zip')
    temp_zip_path = temp_zip.name
    
    try:
        # 创建zip文件
        with zipfile.ZipFile(temp_zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            for file_path in package_dir.rglob('*'):
                if file_path.is_file():
                    # 计算相对路径
                    arcname = file_path.relative_to(package_dir)
                    zf.write(file_path, arcname)
        
        # 关闭临时文件
        temp_zip.close()
        
        # 发送文件
        response = send_from_directory(
            directory=os.path.dirname(temp_zip_path),
            path=os.path.basename(temp_zip_path),
            as_attachment=True,
            download_name=f'{name}-{version}.zip'
        )
        
        # 添加清理回调
        @response.call_on_close
        def cleanup():
            try:
                os.unlink(temp_zip_path)
            except:
                pass
        
        return response
        
    except Exception as e:
        # 确保临时文件被清理
        if os.path.exists(temp_zip_path):
            os.unlink(temp_zip_path)
        app.logger.error(f'创建下载文件失败: {str(e)}')
        abort(500)

@app.route('/<lang>/search', strict_slashes=False)
def search():
    """搜索包"""
    query = request.args.get('q', '').strip()
    
    if not query:
        return redirect(url_for('index', lang=g.lang))
    
    conn = get_db()
    
    # 使用LIKE进行简单搜索，返回每个包的最新版本
    search_pattern = f'%{query}%'
    results = conn.execute('''
        SELECT p.*, u.login AS owner_name
        FROM packages p
        JOIN users u ON p.owner_id = u.id
        WHERE p.name LIKE ?
        AND p.id = (
            SELECT MAX(id)
            FROM packages p2
            WHERE p2.name = p.name
        )
        ORDER BY p.id DESC
    ''', (search_pattern, )).fetchall()
    
    conn.close()

    for i, pkg in enumerate(results):
        pkg = dict(pkg)
        path = Path("pkgs") / pkg["name"] / pkg["version"]
        info = get_package_json(path, path.stat().st_mtime)
        if info:
            pkg.update(info)
        results[i] = pkg
    
    return render_template('search.html',
                         query=query,
                         results=results,
                         user=get_current_user())

# ---------- SEO优化 ----------
@app.route('/robots.txt')
def robots():
    return Response(
        "User-agent: *\n"
        "Allow: /\n"
        "Sitemap: https://upypi.net/sitemap.xml\n",
        mimetype="text/plain"
    )

@app.route('/sitemap.xml')
def sitemap():
    conn = get_db()

    # 获取所有包
    packages = conn.execute('''
        SELECT name, version, created_at
        FROM packages
        ORDER BY created_at DESC
    ''').fetchall()

    conn.close()

    pages = []

    # 首页
    for lang in ['en', 'zh']:
        pages.append({
            "loc": url_for('index', lang=lang, _external=True),
            "lastmod": datetime.utcnow().date().isoformat()
        })

    # 包页面
    for pkg in packages:
        name = pkg["name"]
        version = pkg["version"]

        for lang in ['en', 'zh']:
            pages.append({
                "loc": url_for('package_detail', name=name, version=version, lang=lang, _external=True),
                "lastmod": pkg["created_at"]
            })

    # 生成 XML
    xml = ['<?xml version="1.0" encoding="UTF-8"?>']
    xml.append('<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">')

    for page in pages:
        xml.append("<url>")
        xml.append(f"<loc>{page['loc']}</loc>")
        xml.append(f"<lastmod>{page['lastmod']}</lastmod>")
        xml.append("</url>")

    xml.append("</urlset>")

    return Response("\n".join(xml), mimetype="application/xml")

# ---------- API 端点 ----------
@app.route('/api/search')
def api_search():
    """API 搜索接口"""
    query = request.args.get('q', '').strip()

    if not query:
        return jsonify({
            "query": query,
            "results": []
        })

    conn = get_db()

    search_pattern = f'%{query}%'

    rows = conn.execute('''
    SELECT name, version
    FROM packages p
    WHERE name LIKE ?
    AND id = (
        SELECT MAX(id)
        FROM packages p2
        WHERE p2.name = p.name
    )
    ''', (search_pattern,)).fetchall()

    conn.close()

    results = []

    for row in rows:
        name = row["name"]
        version = row["version"]

        results.append({
            "name": name,
            "url": f"https://upypi.net/pkgs/{name}/{version}"
        })

    return jsonify({
        "query": query,
        "results": results
    })

# ---------- 包文件公开 ----------
@app.route('/pkgs/<path:filename>')
def serve_packages(filename):
    """提供包文件的静态访问"""
    return send_from_directory('pkgs', filename)

# ---------- 错误处理 ----------
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html', user=get_current_user()), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html', user=get_current_user()), 500

if __name__ == '__main__':
    # 运行应用
    app.run(host="127.0.0.1", port=5000)