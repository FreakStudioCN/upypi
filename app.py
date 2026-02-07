import os
import json
import shutil
import sqlite3
from pathlib import Path
from datetime import datetime
from functools import wraps
import markdown
from markdown.extensions.codehilite import CodeHiliteExtension
from markdown.extensions.extra import ExtraExtension

from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, abort
import requests

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
app.secret_key = FLASK_SECRET

# ---------- 上下文处理器，为所有模板添加当前时间 ----------
@app.context_processor
def inject_now():
    """为所有模板注入当前时间"""
    return {'now': datetime.now()}

# ---------- 数据库初始化 ----------
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
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (owner_id) REFERENCES users (id),
            UNIQUE(name, version)
        )
    ''')
    
    conn.commit()
    conn.close()

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
            flash('请先登录', 'error')
            return redirect(url_for('login'))
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

def save_package_files(package_name, version, files):
    """保存上传的包文件"""
    # 版本目录
    version_dir = Path('pkgs') / package_name / version
    version_dir.mkdir(parents=True, exist_ok=True)
    
    # 包根目录（最新版本）
    package_root_dir = Path('pkgs') / package_name
    
    # 保存所有文件，处理路径
    for file in files:
        if file.filename:
            # 处理文件路径，去掉最外层目录
            file_path = file.filename.replace('\\', '/')
            
            # 如果有路径分隔符，去掉第一个部分（最外层目录）
            if '/' in file_path:
                parts = file_path.split('/')
                if len(parts) > 1:
                    # 去掉第一部分（最外层目录）
                    rel_path = '/'.join(parts[1:])
                else:
                    rel_path = file_path
            else:
                rel_path = file_path
            
            if rel_path:  # 确保不是空路径
                # 保存到版本目录
                target_version_path = version_dir / rel_path
                target_version_path.parent.mkdir(parents=True, exist_ok=True)
                file.save(str(target_version_path))
                
                # 如果是第一次保存或需要覆盖，也保存到包根目录（最新版本）
                if package_root_dir.exists():
                    # 如果包根目录存在，我们需要更新文件
                    target_root_path = package_root_dir / rel_path
                    target_root_path.parent.mkdir(parents=True, exist_ok=True)
                    # 由于我们可能已经读取了文件内容，需要重新打开文件
                    file.stream.seek(0)  # 重置文件指针
                    file.save(str(target_root_path))
                else:
                    # 包根目录不存在，先保存到版本目录，稍后复制
                    pass
    
    # 如果包根目录不存在，将版本目录复制到包根目录
    if not package_root_dir.exists():
        shutil.copytree(str(version_dir), str(package_root_dir))
    else:
        # 包根目录已存在，确保更新了所有文件
        # 实际上上面的循环已经处理了，但为了安全，我们可以再同步一次
        for item in version_dir.rglob('*'):
            if item.is_file():
                rel_path = item.relative_to(version_dir)
                target_path = package_root_dir / rel_path
                if not target_path.exists() or item.stat().st_mtime > target_path.stat().st_mtime:
                    target_path.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(item, target_path)

def save_package_files_from_dir(package_name, version, source_dir):
    """从源目录复制文件到包目录"""
    # 版本目录
    version_dir = Path('pkgs') / package_name / version
    version_dir.mkdir(parents=True, exist_ok=True)
    
    # 包根目录（最新版本）
    package_root_dir = Path('pkgs') / package_name
    
    # 复制源目录下的所有文件到版本目录
    for item in source_dir.rglob('*'):
        if item.is_file():
            # 保持相对路径
            relative_path = item.relative_to(source_dir)
            target_version_path = version_dir / relative_path
            target_version_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, target_version_path)
    
    # 如果包根目录不存在，将版本目录复制到包根目录
    if not package_root_dir.exists():
        shutil.copytree(str(version_dir), str(package_root_dir))
    else:
        # 更新包根目录的文件
        for item in version_dir.rglob('*'):
            if item.is_file():
                rel_path = item.relative_to(version_dir)
                target_path = package_root_dir / rel_path
                target_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(item, target_path)

def delete_package(package_name):
    """删除包及其所有版本"""
    package_path = Path('pkgs') / package_name
    if package_path.exists():
        shutil.rmtree(str(package_path))
    
    conn = get_db()
    conn.execute('DELETE FROM packages WHERE name = ?', (package_name,))
    conn.commit()
    conn.close()

def extract_package_info(upload_folder):
    """从上传的文件夹中提取package.json信息"""
    # 递归查找package.json
    for root, dirs, files in os.walk(upload_folder):
        if 'package.json' in files:
            package_json_path = Path(root) / 'package.json'
            break
    else:
        return None
    
    try:
        with open(package_json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # 验证必需字段
        if 'name' not in data or 'version' not in data:
            return None
            
        return {
            'name': data['name'],
            'version': data['version'],
            'description': data.get('description', ''),
            'author': data.get('author', ''),
            'url': data.get('url', ''),
            'license': data.get('license', '')
        }
    except (json.JSONDecodeError, KeyError) as e:
        app.logger.error(f'解析package.json失败: {str(e)}')
        return None

# ---------- 路由 ----------
@app.route('/')
def index():
    """首页"""
    conn = get_db()
    
    # 获取最新的包
    recent_packages = conn.execute('''
        SELECT p.*, u.login as owner_name 
        FROM packages p 
        JOIN users u ON p.owner_id = u.id 
        ORDER BY p.created_at DESC 
        LIMIT 10
    ''').fetchall()
    
    # 获取包总数
    total_packages = conn.execute('SELECT COUNT(*) as count FROM packages').fetchone()['count']
    
    conn.close()
    
    return render_template('index.html', 
                         recent_packages=recent_packages,
                         total_packages=total_packages,
                         user=get_current_user())

@app.route('/favicon.ico')
def favicon():
    """处理 favicon 请求，避免 404 错误"""
    return '', 204  # No Content
    #在 static 文件夹中放置一个 favicon.ico 文件 return send_from_directory('static', 'favicon.ico', mimetype='image/vnd.microsoft.icon')

@app.route('/login')
def login():
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

@app.route('/callback')
def callback():
    """GitHub OAuth 回调"""
    code = request.args.get('code')
    state = request.args.get('state')
    
    if not code or state != session.get('oauth_state'):
        flash('OAuth 认证失败 (state mismatch)', 'error')
        return redirect(url_for('index'))
    
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
        flash('OAuth token 错误', 'error')
        return redirect(url_for('index'))
    
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
        flash('GitHub 用户信息获取失败', 'error')
        return redirect(url_for('index'))
    
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
    
    flash(f'欢迎回来，{login_name}!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    """退出登录"""
    session.clear()
    flash('已成功退出登录', 'success')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    """用户仪表板"""
    user = get_current_user()
    
    conn = get_db()
    user_packages = conn.execute('''
        SELECT * FROM packages 
        WHERE owner_id = ? 
        ORDER BY created_at DESC
    ''', (user['id'],)).fetchall()
    
    conn.close()
    
    return render_template('dashboard.html', 
                         user=user,
                         packages=user_packages)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    """上传包"""
    if request.method == 'GET':
        return render_template('upload.html', user=get_current_user())
    
    # POST 请求处理上传
    user = get_current_user()
    
    if 'files' not in request.files:
        flash('没有选择文件', 'error')
        return redirect(request.url)
    
    files = request.files.getlist('files')
    
    # 检查是否选择了文件
    if not files or all(not file.filename for file in files):
        flash('没有选择文件', 'error')
        return redirect(request.url)
    
    # 创建临时目录保存上传的文件
    import tempfile
    import uuid
    temp_dir = Path(tempfile.gettempdir()) / str(uuid.uuid4())
    temp_dir.mkdir(parents=True)
    
    try:
        # 保存上传的文件到临时目录，去掉最外层目录
        # 分析所有文件的路径，找到共同的前缀
        file_paths = []
        for file in files:
            if file.filename:
                # 检查是否有目录分隔符（说明是文件夹上传）
                if '/' in file.filename or '\\' in file.filename:
                    file_paths.append(file.filename.replace('\\', '/'))
                else:
                    file_paths.append(file.filename)
        
        if not file_paths:
            flash('没有有效文件', 'error')
            return redirect(request.url)
        
        # 找到共同的前缀（最外层目录）
        common_prefix = None
        if all('/' in path for path in file_paths):
            # 获取所有路径的第一个目录部分
            first_parts = [path.split('/')[0] for path in file_paths]
            if len(set(first_parts)) == 1:
                common_prefix = first_parts[0] + '/'
        
        # 保存文件，去掉共同的前缀
        for file in files:
            if file.filename:
                # 规范化路径分隔符
                file_path = file.filename.replace('\\', '/')
                
                # 去掉共同的前缀
                if common_prefix and file_path.startswith(common_prefix):
                    rel_path = file_path[len(common_prefix):]
                else:
                    rel_path = file_path
                
                if rel_path:  # 确保不是空路径
                    target_path = temp_dir / rel_path
                    target_path.parent.mkdir(parents=True, exist_ok=True)
                    file.save(str(target_path))
        
        # 提取 package.json 信息
        package_info = extract_package_info(temp_dir)
        if not package_info:
            flash('package.json 文件不存在或格式错误', 'error')
            return redirect(request.url)
        
        package_name = package_info['name']
        package_version = package_info['version']
        
        # 检查是否已存在相同版本的包
        conn = get_db()
        existing = conn.execute(
            'SELECT * FROM packages WHERE name = ? AND version = ?',
            (package_name, package_version)
        ).fetchone()
        
        if existing:
            flash(f'包 {package_name} 版本 {package_version} 已存在', 'error')
            return redirect(request.url)
        
        # 保存到数据库
        cursor = conn.execute(
            '''INSERT INTO packages (name, version, owner_id, description) 
               VALUES (?, ?, ?, ?)''',
            (package_name, package_version, user['id'], package_info['description'])
        )
        
        conn.commit()
        conn.close()
        
        # 保存包文件
        save_package_files_from_dir(package_name, package_version, temp_dir)
        
        flash(f'包 {package_name} v{package_version} 上传成功!', 'success')
        return redirect(url_for('package_detail', name=package_name))
        
    except Exception as e:
        app.logger.error(f'上传包时出错: {str(e)}')
        flash(f'上传失败: {str(e)}', 'error')
        return redirect(request.url)
    finally:
        # 清理临时目录
        if temp_dir.exists():
            shutil.rmtree(str(temp_dir))


def get_package_files(package_name, version='latest'):
    """获取包的文件列表"""
    from pathlib import Path
    
    if version == 'latest':
        # 最新版本的文件在包根目录
        package_dir = Path('pkgs') / package_name
    else:
        # 特定版本的文件在版本目录
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

# 添加 markdown 渲染函数
def render_markdown(content):
    """渲染 Markdown 为 HTML"""
    if not content:
        return ""
    
    try:
        # 配置 markdown 扩展
        extensions = [
            ExtraExtension(),
            CodeHiliteExtension(
                css_class='highlight',
                linenums=False,
                guess_lang=True
            ),
            'fenced_code',
            'tables',
            'toc'
        ]
        
        # 渲染 markdown
        html = markdown.markdown(
            content,
            extensions=extensions,
            output_format='html'
        )
        return html
    except Exception as e:
        app.logger.error(f'Markdown 渲染失败: {str(e)}')
        return f'<pre class="bg-light p-3 border rounded">{content}</pre>'

# 添加 markdown 过滤器
@app.template_filter('markdown')
def markdown_filter(text):
    """Jinja2 模板过滤器：将 markdown 转换为 HTML"""
    return render_markdown(text)

@app.route('/pkgs/<name>')
def package_detail(name):
    """包详情页面"""
    conn = get_db()
    
    # 获取包的基本信息
    package_info = conn.execute('''
        SELECT p.*, u.login as owner_name 
        FROM packages p 
        JOIN users u ON p.owner_id = u.id 
        WHERE p.name = ?
        ORDER BY p.created_at DESC
    ''', (name,)).fetchall()
    
    if not package_info:
        abort(404)
    
    # 获取所有版本
    versions = [row['version'] for row in package_info]
    latest_version = versions[0] if versions else None
    
    conn.close()
    
    # 检查是否有 README.md - 现在从包根目录读取
    readme_content = None
    readme_path = Path('pkgs') / name / 'README.md'
    if readme_path.exists():
        try:
            with open(readme_path, 'r', encoding='utf-8') as f:
                markdown_content = f.read()
                # 渲染 Markdown 为 HTML
                readme_content = render_markdown(markdown_content)
        except Exception as e:
            app.logger.error(f'读取 README.md 失败: {str(e)}')
    
    # 获取最新版本的文件列表 - 现在从包根目录获取
    files = get_package_files(name, 'latest')
    
    return render_template('package.html',
                         package_name=name,
                         packages=package_info,
                         versions=versions,
                         latest_version=latest_version,
                         readme_content=readme_content,
                         files=files,
                         user=get_current_user())

@app.route('/pkgs/<name>/delete', methods=['POST'])
@login_required
def delete_package_route(name):
    """删除包"""
    user = get_current_user()
    
    conn = get_db()
    
    # 检查包是否存在且用户是否有权限
    package = conn.execute(
        'SELECT * FROM packages WHERE name = ? AND owner_id = ?',
        (name, user['id'])
    ).fetchone()
    
    if not package:
        flash('包不存在或没有删除权限', 'error')
        return redirect(url_for('dashboard'))
    
    # 删除包
    delete_package(name)
    
    flash(f'包 {name} 已成功删除', 'success')
    return redirect(url_for('dashboard'))

@app.route('/pkgs/<name>/<version>/download')
def download_package(name, version):
    """下载指定版本的包"""
    # 确定要下载的目录
    if version == 'latest':
        # 下载最新版本（包根目录）
        package_dir = Path('pkgs') / name
    else:
        # 下载特定版本
        package_dir = Path('pkgs') / name / version
    
    if not package_dir.exists():
        abort(404)
    
    # 创建临时zip文件
    import zipfile
    import tempfile
    import os
    
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

@app.route('/search')
def search():
    """搜索包"""
    query = request.args.get('q', '').strip()
    
    if not query:
        return redirect(url_for('index'))
    
    conn = get_db()
    
    # 使用LIKE进行简单搜索
    search_pattern = f'%{query}%'
    results = conn.execute('''
        SELECT p.*, u.login as owner_name 
        FROM packages p 
        JOIN users u ON p.owner_id = u.id 
        WHERE p.name LIKE ? OR p.description LIKE ?
        ORDER BY p.created_at DESC
    ''', (search_pattern, search_pattern)).fetchall()
    
    conn.close()
    
    return render_template('search.html',
                         query=query,
                         results=results,
                         user=get_current_user())

# ---------- 错误处理 ----------
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html', user=get_current_user()), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html', user=get_current_user()), 500

if __name__ == '__main__':
    # 初始化数据库
    init_db()
    
    # 运行应用
    app.run(host="127.0.0.1", port=5000)