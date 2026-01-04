import os
import shutil
import mimetypes
import markdown
import time
from datetime import datetime, timedelta
from flask import Flask, render_template, send_from_directory, abort, request, jsonify, session, redirect, url_for, \
    flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text, inspect

app = Flask(__name__)

# ================= 核心安全配置 =================
app.secret_key = os.urandom(24)

# 容器内固定路径 (无需修改，部署时通过 Docker 挂载到这两处)
DATA_DIR = "/app/data"
BASE_DIR = "/app/shares"

# 确保目录在容器内存在
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(BASE_DIR, exist_ok=True)

CONFIG_FILE = os.path.join(DATA_DIR, 'nexus.conf')


def get_config():
    defaults = {'user_password': '123456', 'admin_password': 'admin'}
    if not os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                f.write("# 派大星网盘 配置文件\n")
                f.write(f"user_password={defaults['user_password']}\n")
                f.write(f"admin_password={defaults['admin_password']}\n")
        except:
            pass
        return defaults
    config = defaults.copy()
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'): continue
                if '=' in line:
                    key, value = line.split('=', 1)
                    config[key.strip()] = value.strip()
    except:
        pass
    return config


# ================= 数据库配置 =================
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(DATA_DIR, "logs.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JSON_AS_ASCII'] = False

db = SQLAlchemy(app)


class DownloadLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200))
    ip_address = db.Column(db.String(50))
    action = db.Column(db.String(20))
    timestamp = db.Column(db.DateTime, default=datetime.now)


def check_and_update_db():
    with app.app_context():
        db.create_all()
        inspector = inspect(db.engine)
        columns = [c['name'] for c in inspector.get_columns('download_log')]
        if 'action' not in columns:
            try:
                with db.engine.connect() as conn:
                    conn.execute(text("ALTER TABLE download_log ADD COLUMN action VARCHAR(20)"))
                    conn.execute(text("UPDATE download_log SET action = 'down'"))
                    conn.commit()
            except Exception as e:
                print(f"DB Update Error: {e}")


check_and_update_db()


# ================= 工具函数 =================
def human_readable_size(size):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024: return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def get_file_type(filename):
    ext = os.path.splitext(filename)[1].lower()
    if ext in ['.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg']: return 'image'
    if ext in ['.mp4', '.mkv', '.avi', '.mov', '.webm']: return 'video'
    if ext in ['.mp3', '.wav', '.flac']: return 'audio'
    if ext in ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx']: return 'doc'
    if ext in ['.txt', '.md', '.json', '.xml', '.py', '.js', '.html', '.css']: return 'code'
    if ext in ['.zip', '.rar', '.7z', '.tar', '.gz']: return 'archive'
    return 'file'


def get_disk_usage():
    try:
        total, used, free = shutil.disk_usage(BASE_DIR)
        return {'total': human_readable_size(total), 'used': human_readable_size(used),
                'percent': round((used / total) * 100, 1)}
    except:
        return {'total': 'N/A', 'used': 'N/A', 'percent': 0}


# ================= 权限拦截 =================
@app.before_request
def require_login():
    allowed_endpoints = ['login', 'admin_login', 'static']
    if request.endpoint not in allowed_endpoints and not session.get('is_verified'):
        return redirect(url_for('login', next=request.url))


# ================= 路由 =================
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        input_pwd = request.form.get('password', '').strip()
        config = get_config()
        if input_pwd == config['user_password']:
            session['is_verified'] = True
            log = DownloadLog(filename='User Login', ip_address=request.remote_addr, action='login')
            db.session.add(log);
            db.session.commit()
            return redirect(request.args.get('next') or url_for('index'))
        else:
            time.sleep(1);
            flash('访问口令错误', 'error')
    return render_template('login.html', title="安全访问验证", subtitle="请输入访问口令以继续")


@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if session.get('is_admin'): return redirect(url_for('admin_dashboard'))
    if request.method == 'POST':
        if request.form.get('password', '').strip() == get_config()['admin_password']:
            session['is_admin'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            flash('管理员口令错误', 'error')
    return render_template('login.html', title="管理后台验证", subtitle="请输入管理员口令")


@app.route('/logout')
def logout():
    session.clear();
    return redirect(url_for('login'))


@app.route('/admin')
def admin_dashboard():
    if not session.get('is_admin'): return redirect(url_for('admin_login'))
    logs = DownloadLog.query.order_by(DownloadLog.timestamp.desc()).limit(100).all()
    stats = {
        'total_downloads': DownloadLog.query.filter_by(action='down').count(),
        'total_views': DownloadLog.query.filter_by(action='view').count(),
        'total_logins': DownloadLog.query.filter_by(action='login').count(),
        'disk': get_disk_usage()
    }
    return render_template('admin.html', stats=stats, logs=logs)


@app.route('/', defaults={'req_path': ''})
@app.route('/browse/', defaults={'req_path': ''})
@app.route('/browse/<path:req_path>')
def index(req_path):
    if '..' in req_path: abort(403)
    full_path = os.path.join(BASE_DIR, req_path)
    if not os.path.exists(full_path): abort(404)
    if os.path.isfile(full_path): return serve_file(req_path, True)

    items = []
    readme_content = None
    stats = {'total': 0, 'image': 0, 'video': 0, 'doc': 0}
    three_days_ago = datetime.now() - timedelta(days=3)

    try:
        with os.scandir(full_path) as it:
            for entry in it:
                if entry.name.startswith('.'): continue
                if entry.name.lower() == 'readme.md':
                    try:
                        with open(entry.path, 'r', encoding='utf-8') as f:
                            readme_content = markdown.markdown(f.read(), extensions=['fenced_code', 'tables'])
                    except:
                        pass

                is_dir = entry.is_dir()
                ftype = 'folder' if is_dir else get_file_type(entry.name)
                stat = entry.stat()
                stats['total'] += 1
                if ftype in stats: stats[ftype] += 1

                items.append({
                    'name': entry.name, 'type': ftype, 'is_dir': is_dir,
                    'size': human_readable_size(stat.st_size) if not is_dir else '-',
                    'mtime': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M'),
                    'rel_path': os.path.join(req_path, entry.name).replace('\\', '/').strip('/'),
                    'is_new': datetime.fromtimestamp(stat.st_mtime) > three_days_ago
                })
    except PermissionError:
        pass
    items.sort(key=lambda x: (not x['is_dir'], x['name'].lower()))

    breadcrumbs = []
    parts = [p for p in req_path.split('/') if p]
    curr = ""
    for p in parts:
        curr = f"{curr}/{p}".strip('/')
        breadcrumbs.append({'name': p, 'path': curr})

    return render_template('index.html', items=items, breadcrumbs=breadcrumbs, disk=get_disk_usage(),
                           readme=readme_content, stats=stats, current_path=req_path)


@app.route('/api/search')
def search():
    query = request.args.get('q', '').lower()
    if not query: return jsonify([])
    results = []
    for root, dirs, files in os.walk(BASE_DIR):
        dirs[:] = [d for d in dirs if not d.startswith('.')]
        for name in files + dirs:
            if query in name.lower():
                full_path = os.path.join(root, name)
                is_dir = os.path.isdir(full_path)
                results.append({
                    'name': name, 'is_dir': is_dir, 'type': 'folder' if is_dir else get_file_type(name),
                    'rel_path': os.path.relpath(full_path, BASE_DIR).replace('\\', '/'),
                    'size': human_readable_size(os.path.getsize(full_path)) if not is_dir else '-'
                })
                if len(results) >= 30: break
        if len(results) >= 30: break
    return jsonify(results)


@app.route('/download/<path:req_path>')
def download(req_path): return serve_file(req_path, True)


@app.route('/view/<path:req_path>')
def view(req_path): return serve_file(req_path, False)


def serve_file(req_path, as_attachment):
    if '..' in req_path: abort(403)
    full_path = os.path.join(BASE_DIR, req_path)
    try:
        log = DownloadLog(filename=req_path, ip_address=request.remote_addr, action='down' if as_attachment else 'view')
        db.session.add(log);
        db.session.commit()
    except:
        pass
    return send_from_directory(os.path.dirname(full_path), os.path.basename(full_path), as_attachment=as_attachment)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
