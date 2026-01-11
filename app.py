import os
import shutil
import mimetypes
import markdown
import time
import secrets
import logging
import sys
import uuid
from datetime import datetime, timedelta
from flask import Flask, render_template, send_from_directory, abort, request, jsonify, session, redirect, url_for, \
    flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text, inspect
from werkzeug.middleware.proxy_fix import ProxyFix

# ================= 日志配置 =================
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
app.logger.setLevel(logging.DEBUG)

# ================= 核心配置 =================
app.secret_key = "nexus-drive-fixed-secret"
# 这里也设置大一点，防止 Flask 层面限制上传
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 * 1024 

DATA_DIR = "/app/data"
BASE_DIR = "/app/shares"

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(BASE_DIR, exist_ok=True)

CONFIG_FILE = os.path.join(DATA_DIR, 'nexus.conf')

def get_config():
    defaults = {'user_password': '123456', 'admin_password': 'admin'}
    if not os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                f.write(f"user_password={defaults['user_password']}\n")
                f.write(f"admin_password={defaults['admin_password']}\n")
        except Exception as e:
            app.logger.error(f"Config write error: {e}")
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
    except Exception as e:
        app.logger.error(f"Config read error: {e}")
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

class FileShare(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_path = db.Column(db.String(500), nullable=False)
    slug = db.Column(db.String(50), unique=True, nullable=False)
    expire_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now)
    downloads = db.Column(db.Integer, default=0)

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
                app.logger.error(f"DB Update Error: {e}")

check_and_update_db()

@app.context_processor
def inject_global_vars():
    return dict(is_admin=session.get('is_admin', False))

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

def secure_path(path):
    if path is None: return ''
    path = path.strip('/')
    if '..' in path or path.startswith('/') or path.startswith('\\'):
        return None
    return path

def is_mobile_device():
    if request.args.get('view') == 'mobile':
        return True
    ua = request.headers.get('User-Agent', '').lower()
    if not ua and request.user_agent:
        ua = request.user_agent.string.lower()
    if not ua: return False
    mobile_keywords = [
        'android', 'iphone', 'ipod', 'ipad', 'windows phone', 
        'blackberry', 'mobile', 'webos', 'micromessenger', 
        'symbian', 'netfront', 'midp', 'wap', 'opera mini', 'ucbrowser'
    ]
    return any(keyword in ua for keyword in mobile_keywords)

@app.before_request
def log_request_info():
    if not request.path.startswith('/static'):
        ua = request.headers.get('User-Agent', 'No-UA-Header')
        app.logger.debug(f"REQ: {request.method} {request.path} | IP: {request.remote_addr} | Mobile: {is_mobile_device()} | UA: {ua}")

# ================= 接口部分 =================

@app.route('/admin/file/mkdir', methods=['POST'])
def create_folder():
    if not session.get('is_admin'): return jsonify({'error': '无权操作'}), 403
    data = request.json
    path = secure_path(data.get('path', ''))
    name = data.get('name', '').strip()
    if path is None: return jsonify({'error': '非法路径'}), 400
    if not name or '..' in name or '/' in name or '\\' in name: 
        return jsonify({'error': '文件夹名称非法'}), 400
    full_path = os.path.join(BASE_DIR, path, name)
    try:
        os.makedirs(full_path, exist_ok=False)
        return jsonify({'success': True})
    except FileExistsError:
        return jsonify({'error': '该文件夹已存在'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/admin/file/upload', methods=['POST'])
def upload_file():
    if not session.get('is_admin'): return jsonify({'error': '无权操作'}), 403
    try:
        path = secure_path(request.form.get('path', ''))
        if path is None: return jsonify({'error': '非法路径'}), 400
        upload_dir = os.path.join(BASE_DIR, path)
        if not os.path.exists(upload_dir):
            return jsonify({'error': '目录不存在'}), 404
        files = request.files.getlist('files')
        saved_count = 0
        for file in files:
            if file and file.filename:
                filename = os.path.basename(file.filename)
                filename = filename.replace('..', '').replace('/', '').replace('\\', '')
                if not filename: filename = f"upload_{int(time.time())}_{secrets.token_hex(4)}"
                save_path = os.path.join(upload_dir, filename)
                base, ext = os.path.splitext(filename)
                counter = 1
                while os.path.exists(save_path):
                    save_path = os.path.join(upload_dir, f"{base}_{counter}{ext}")
                    counter += 1
                file.save(save_path)
                saved_count += 1
        return jsonify({'success': True, 'count': saved_count})
    except Exception as e:
        app.logger.error(f"Upload Error: {str(e)}")
        return jsonify({'error': f"上传出错: {str(e)}"}), 500

@app.route('/admin/file/rename', methods=['POST'])
def rename_item():
    if not session.get('is_admin'): return jsonify({'error': '无权操作'}), 403
    data = request.json
    path = secure_path(data.get('path', ''))
    old_name = data.get('old_name', '').strip()
    new_name = data.get('new_name', '').strip()
    if path is None or not old_name or not new_name: return jsonify({'error': '参数错误'}), 400
    if '..' in new_name or '/' in new_name or '\\' in new_name: return jsonify({'error': '新名称非法'}), 400
    old_path = os.path.join(BASE_DIR, path, old_name)
    new_path = os.path.join(BASE_DIR, path, new_name)
    if not os.path.exists(old_path): return jsonify({'error': '原文件不存在'}), 404
    if os.path.exists(new_path): return jsonify({'error': '新名称已存在'}), 400
    try:
        os.rename(old_path, new_path)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/admin/file/delete', methods=['POST'])
def delete_items():
    if not session.get('is_admin'): return jsonify({'error': '无权操作'}), 403
    data = request.json
    path = secure_path(data.get('path', ''))
    filenames = data.get('filenames', [])
    if path is None or not filenames: return jsonify({'error': '参数错误'}), 400
    success_count = 0
    errors = []
    for name in filenames:
        if '..' in name or '/' in name: continue
        full_path = os.path.join(BASE_DIR, path, name)
        try:
            if os.path.isfile(full_path) or os.path.islink(full_path):
                os.remove(full_path)
            elif os.path.isdir(full_path):
                shutil.rmtree(full_path)
            success_count += 1
        except Exception as e:
            errors.append(f"{name}: {str(e)}")
    if errors:
        return jsonify({'success': False, 'msg': f"部分删除失败: {'; '.join(errors)}"})
    return jsonify({'success': True})

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        input_pwd = request.form.get('password', '').strip()
        config = get_config()
        if input_pwd == config['user_password']:
            session['is_verified'] = True
            log = DownloadLog(filename='User Login', ip_address=request.remote_addr, action='login')
            db.session.add(log); db.session.commit()
            return redirect(request.args.get('next') or '/')
        else:
            time.sleep(1); flash('访问口令错误', 'error')
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
    session.clear()
    return redirect(url_for('login'))

@app.route('/admin')
def admin_dashboard():
    if not session.get('is_admin'): return redirect(url_for('admin_login'))
    
    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 20, type=int)
    if limit not in [20, 50, 100]: limit = 20
    
    pagination = DownloadLog.query.order_by(DownloadLog.timestamp.desc()).paginate(
        page=page, per_page=limit, error_out=False
    )
    
    shares = FileShare.query.order_by(FileShare.created_at.desc()).all()
    now = datetime.now()
    for s in shares: s.is_expired = s.expire_at and s.expire_at < now
    
    stats = {
        'total_downloads': DownloadLog.query.filter_by(action='down').count(),
        'total_views': DownloadLog.query.filter_by(action='view').count(),
        'total_logins': DownloadLog.query.filter_by(action='login').count(),
        'disk': get_disk_usage()
    }
    
    # 只要是移动设备，就强制显示移动端后台
    if is_mobile_device():
        return render_template('mobile_admin.html', 
                             stats=stats, pagination=pagination, 
                             limit=limit, shares=shares, now=now)
    
    return render_template('admin.html', stats=stats, pagination=pagination, limit=limit, shares=shares, now=now)

@app.route('/admin/share/create', methods=['POST'])
def create_share():
    if not session.get('is_admin'): 
        if request.is_json: return jsonify({'error': '无权操作'}), 403
        abort(403)
    data = request.json if request.is_json else request.form
    file_path = data.get('file_path', '').strip()
    slug = data.get('slug', '').strip()
    duration = data.get('duration')
    full_path = os.path.join(BASE_DIR, file_path)
    if not os.path.exists(full_path) or not os.path.isfile(full_path):
        msg = '文件不存在'
        if request.is_json: return jsonify({'error': msg}), 404
        flash(msg, 'error')
        return redirect(url_for('admin_dashboard'))
    if not slug: slug = secrets.token_urlsafe(6)
    if FileShare.query.filter_by(slug=slug).first():
        msg = '该后缀已被使用，请更换'
        if request.is_json: return jsonify({'error': msg}), 400
        flash(msg, 'error')
        return redirect(url_for('admin_dashboard'))
    expire_at = None
    if duration and duration != 'forever':
        try: expire_at = datetime.now() + timedelta(days=int(duration))
        except: pass
    new_share = FileShare(file_path=file_path, slug=slug, expire_at=expire_at)
    db.session.add(new_share); db.session.commit()
    share_url = url_for('index', req_path=slug, _external=True)
    if request.is_json: return jsonify({'success': True, 'url': share_url})
    flash(f'分享链接创建成功', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/share/edit', methods=['POST'])
def edit_share():
    if not session.get('is_admin'): abort(403)
    share_id = request.form.get('id')
    slug = request.form.get('slug', '').strip()
    duration = request.form.get('duration')
    share = FileShare.query.get_or_404(share_id)
    existing = FileShare.query.filter_by(slug=slug).first()
    if existing and existing.id != share.id:
        flash('修改失败：该后缀已被其他分享使用', 'error')
        return redirect(url_for('admin_dashboard'))
    share.slug = slug
    if duration:
        if duration == 'forever': share.expire_at = None
        else:
            try: share.expire_at = datetime.now() + timedelta(days=int(duration))
            except: pass
    db.session.commit()
    flash('分享链接已更新', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/share/delete/<int:id>')
def delete_share(id):
    if not session.get('is_admin'): abort(403)
    share = FileShare.query.get_or_404(id)
    db.session.delete(share); db.session.commit()
    flash('分享链接已删除', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/', defaults={'req_path': ''})
@app.route('/<path:req_path>')
def index(req_path):
    if req_path and '..' not in req_path:
        share = FileShare.query.filter_by(slug=req_path).first()
        if share:
            if share.expire_at and share.expire_at < datetime.now(): return "该分享链接已过期", 410
            full_path = os.path.join(BASE_DIR, share.file_path)
            if not os.path.exists(full_path): return "原文件已被移动或删除", 404
            share.downloads += 1
            log = DownloadLog(filename=f"[Share] {share.file_path}", ip_address=request.remote_addr, action='share_down')
            db.session.add(log); db.session.commit()
            return send_from_directory(os.path.dirname(full_path), os.path.basename(full_path), as_attachment=True)

    if not session.get('is_verified'):
        return redirect(url_for('login', next=request.path))

    req_path = secure_path(req_path)
    if req_path is None: abort(403)
    full_path = os.path.join(BASE_DIR, req_path)
    if not os.path.exists(full_path): abort(404)
    if os.path.isfile(full_path): return serve_file(req_path, True)

    items = []
    readme_content = None
    stats = {'total': 0, 'image': 0, 'video': 0, 'doc': 0}
    try:
        with os.scandir(full_path) as it:
            for entry in it:
                if entry.name.startswith('.'): continue
                if entry.name.lower() == 'readme.md':
                    try:
                        with open(entry.path, 'r', encoding='utf-8') as f:
                            readme_content = markdown.markdown(f.read(), extensions=['fenced_code', 'tables'])
                    except: pass
                is_dir = entry.is_dir()
                ftype = 'folder' if is_dir else get_file_type(entry.name)
                stat = entry.stat()
                stats['total'] += 1
                if ftype in stats: stats[ftype] += 1
                items.append({
                    'name': entry.name, 'type': ftype, 'is_dir': is_dir,
                    'size': human_readable_size(stat.st_size) if not is_dir else '-',
                    'mtime': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M'),
                    'rel_path': os.path.join(req_path, entry.name).replace('\\', '/').strip('/')
                })
    except PermissionError: pass
    items.sort(key=lambda x: (not x['is_dir'], x['name'].lower()))

    breadcrumbs = []
    parts = [p for p in req_path.split('/') if p]
    curr = ""
    for p in parts:
        curr = f"{curr}/{p}".strip('/')
        breadcrumbs.append({'name': p, 'path': curr})
    
    # 只要是移动设备，就强制显示移动端页面
    if is_mobile_device():
        return render_template('mobile_index.html', items=items, breadcrumbs=breadcrumbs, 
                             readme=readme_content, current_path=req_path, stats=stats, is_admin=session.get('is_admin', False))

    return render_template('index.html', items=items, breadcrumbs=breadcrumbs, disk=get_disk_usage(),
                           readme=readme_content, stats=stats, current_path=req_path)

@app.route('/api/search')
def search():
    if not session.get('is_verified'): return jsonify([])
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
def download(req_path): 
    if not session.get('is_verified'): return redirect(url_for('login'))
    return serve_file(req_path, True)

@app.route('/view/<path:req_path>')
def view(req_path): 
    if not session.get('is_verified'): return redirect(url_for('login'))
    return serve_file(req_path, False)

def serve_file(req_path, as_attachment):
    if '..' in req_path: abort(403)
    full_path = os.path.join(BASE_DIR, req_path)
    try:
        log = DownloadLog(filename=req_path, ip_address=request.remote_addr, action='down' if as_attachment else 'view')
        db.session.add(log); db.session.commit()
    except: pass
    return send_from_directory(os.path.dirname(full_path), os.path.basename(full_path), as_attachment=as_attachment)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
