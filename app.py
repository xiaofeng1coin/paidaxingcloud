import json
import os
import re
import shutil
import hmac
import threading
import mimetypes
import markdown
import bleach
import time
import secrets
import logging
import sys
import uuid
import requests
import traceback
from datetime import datetime, timedelta
from flask import Flask, render_template, send_from_directory, abort, request, jsonify, session, redirect, url_for, \
    flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text, inspect, event
from sqlalchemy.engine import Engine
from werkzeug.middleware.proxy_fix import ProxyFix

# ================= 日志配置 =================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)

app = Flask(__name__)
# 适配反向代理 (Nginx/Cloudflare)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
app.logger.setLevel(logging.INFO)

# ================= 核心配置 =================
# 设置大一点，防止 Flask 层面限制上传
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 * 1024

DATA_DIR = "/app/data"
BASE_DIR = "/app/shares"

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(BASE_DIR, exist_ok=True)

# 优化(P2-9)：会话安全配置
app.config.update(
    SESSION_COOKIE_SAMESITE='Lax',     # CSRF 纵深防御（与 token 双保险）
    SESSION_COOKIE_HTTPONLY=True,
    # 登录成功时 session.permanent=True，实现 7 天免登录
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),
)
# SESSION_COOKIE_SECURE 按部署环境决定：默认关闭以兼容内网 http 访问；
# 全站 HTTPS（含内网）时设置环境变量 NEXUS_COOKIE_SECURE=1 开启，cookie 仅经 HTTPS 传输
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('NEXUS_COOKIE_SECURE', '').strip().lower() in ('1', 'true', 'yes', 'on')

def load_or_create_secret():
    """安全修复(P0-3)：会话密钥不再硬编码在源码中。
    首次启动随机生成并持久化到数据目录 secret.key。
    注意：密钥更换后，所有已登录会话将自动失效。"""
    secret_file = os.path.join(DATA_DIR, 'secret.key')
    try:
        if os.path.exists(secret_file):
            with open(secret_file, 'r', encoding='utf-8') as f:
                key = f.read().strip()
            if key:
                return key
        key = secrets.token_hex(32)
        with open(secret_file, 'w', encoding='utf-8') as f:
            f.write(key)
        return key
    except Exception as e:
        app.logger.error(f"Secret key load/create error: {e}")
        return secrets.token_hex(32)

app.secret_key = load_or_create_secret()

CONFIG_FILE = os.path.join(DATA_DIR, 'nexus.conf')

# 优化(P2-2)：配置文件 mtime 缓存——外部直接编辑 nexus.conf 后自动重新加载，保存即生效
_config_cache = {'data': None, 'mtime': None}

def get_config():
    defaults = {'user_password': '123456', 'admin_password': 'admin'}
    try:
        mtime = os.stat(CONFIG_FILE).st_mtime
    except OSError:
        try:
            with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                f.write(f"user_password={defaults['user_password']}\n")
                f.write(f"admin_password={defaults['admin_password']}\n")
            mtime = os.stat(CONFIG_FILE).st_mtime
        except Exception as e:
            app.logger.error(f"Config write error: {e}")
            return defaults
    if _config_cache['data'] is not None and _config_cache['mtime'] == mtime:
        return _config_cache['data']
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
    _config_cache['data'] = config
    _config_cache['mtime'] = mtime
    return config

# ================= 时间工具 =================
def get_beijing_time():
    """获取北京时间 (UTC+8)"""
    return datetime.utcnow() + timedelta(hours=8)

# ================= 数据库配置 =================
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(DATA_DIR, "logs.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# 修复(P1-9)：Flask 2.3 起 JSON_AS_ASCII 已废弃，改用新写法使中文不再转义为 \uXXXX
app.json.ensure_ascii = False

db = SQLAlchemy(app)

# 优化(P2-1)：SQLite 开启 WAL 与忙等超时，缓解多 worker 与后台回写线程并发写的锁冲突
@event.listens_for(Engine, 'connect')
def _sqlite_pragma(dbapi_connection, connection_record):
    if type(dbapi_connection).__module__.startswith('sqlite3'):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.close()

# 新增：用于存储历史统计数据的模型
class SystemStat(db.Model):
    key = db.Column(db.String(50), primary_key=True) # 例如 'total_downloads'
    value = db.Column(db.Integer, default=0)

class DownloadLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200))
    ip_address = db.Column(db.String(50))
    action = db.Column(db.String(20))
    ip_location = db.Column(db.String(100), default='未知')
    device_type = db.Column(db.String(100), default='未知')
    timestamp = db.Column(db.DateTime, default=get_beijing_time)

class FileShare(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_path = db.Column(db.String(500), nullable=False)
    slug = db.Column(db.String(50), unique=True, nullable=False)
    expire_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=get_beijing_time)
    downloads = db.Column(db.Integer, default=0)

def check_and_update_db():
    """
    启动时检查数据库结构
    """
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
            except Exception as e: app.logger.error(f"DB Update Action Error: {e}")
            
        if 'ip_location' not in columns:
            try:
                with db.engine.connect() as conn:
                    conn.execute(text("ALTER TABLE download_log ADD COLUMN ip_location VARCHAR(100)"))
                    conn.commit()
            except Exception as e: app.logger.error(f"DB Update Location Error: {e}")

        if 'device_type' not in columns:
            try:
                with db.engine.connect() as conn:
                    conn.execute(text("ALTER TABLE download_log ADD COLUMN device_type VARCHAR(100)"))
                    conn.commit()
            except Exception as e: app.logger.error(f"DB Update Device Error: {e}")

check_and_update_db()

# ================= 统计工具函数 =================

def get_archived_stat(key):
    """获取归档的历史统计数据"""
    stat = SystemStat.query.get(key)
    return stat.value if stat else 0

def update_archived_stat(key, count):
    """累加历史统计数据"""
    if count == 0: return
    stat = SystemStat.query.get(key)
    if not stat:
        stat = SystemStat(key=key, value=0)
        db.session.add(stat)
    stat.value += count

# ================= 登录防爆破 =================

class LoginGuard:
    """内存级登录防爆破：同一来源连续失败达到上限后锁定一段时间"""
    def __init__(self, max_attempts=5, lock_seconds=600):
        self.max_attempts = max_attempts
        self.lock_seconds = lock_seconds
        self.records = {}

    def is_locked(self, ip):
        """返回剩余锁定秒数，未锁定返回 0"""
        rec = self.records.get(ip)
        if not rec: return 0
        locked_until = rec.get('locked_until', 0)
        if locked_until and time.time() < locked_until:
            return int(locked_until - time.time()) + 1
        return 0

    def record_failure(self, ip):
        rec = self.records.setdefault(ip, {'count': 0, 'locked_until': 0})
        rec['count'] += 1
        if rec['count'] >= self.max_attempts:
            rec['locked_until'] = time.time() + self.lock_seconds
            rec['count'] = 0

    def record_success(self, ip):
        self.records.pop(ip, None)

login_guard = LoginGuard(max_attempts=5, lock_seconds=600)

# ================= CSRF 防护 =================

def get_csrf_token():
    """按会话生成/获取 CSRF token（页面渲染时建立，AJAX/表单共用）"""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)
    return session['csrf_token']

def _extract_csrf_from_request():
    token = request.headers.get('X-CSRF-Token', '')
    if not token and request.form:
        token = request.form.get('csrf_token', '')
    if not token:
        body = request.get_json(silent=True)
        if isinstance(body, dict):
            token = body.get('csrf_token', '')
    return token or ''

# ================= 常用工具函数 =================

def get_real_ip():
    if 'CF-Connecting-IP' in request.headers:
        return request.headers.get('CF-Connecting-IP')
    if 'X-Forwarded-For' in request.headers:
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr

# 修复(P1-6)：IP 归属地进程内缓存，避免同一 IP 反复请求外部接口
IP_LOCATION_CACHE = {}
IP_LOCATION_CACHE_MAX = 2000
IP_LOCATION_TTL = 24 * 3600  # 24 小时

def get_ip_location_info(ip):
    if ip in ['127.0.0.1', 'localhost', '::1'] or ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.'):
        return "内网/本地"
    now_ts = time.time()
    cached = IP_LOCATION_CACHE.get(ip)
    if cached and now_ts - cached[1] < IP_LOCATION_TTL:
        return cached[0]
    location = _query_ip_location(ip)
    if location != "未知":
        if len(IP_LOCATION_CACHE) >= IP_LOCATION_CACHE_MAX:
            for k in list(IP_LOCATION_CACHE.keys())[:IP_LOCATION_CACHE_MAX // 2]:
                IP_LOCATION_CACHE.pop(k, None)
        IP_LOCATION_CACHE[ip] = (location, now_ts)
    return location

def _query_ip_location(ip):
    try:
        url = "https://whois.pconline.com.cn/ipJson.jsp"
        params = {'ip': ip, 'json': 'true'}
        headers = {'User-Agent': 'Mozilla/5.0'}
        resp = requests.get(url, params=params, headers=headers, timeout=3)
        if resp.status_code == 200:
            content = resp.content.decode('gbk', 'ignore').strip()
            data = json.loads(content)
            if 'addr' in data and data['addr']:
                return data['addr'].strip()
            if 'pro' in data or 'city' in data:
                return f"{data.get('pro','')} {data.get('city','')}".strip()
    except Exception as e:
        app.logger.error(f"IP Query Error: {str(e)}")
    return "未知"

def get_device_info():
    ua = request.user_agent
    ua_str = request.headers.get('User-Agent', '').lower()
    platform = ua.platform
    browser = ua.browser
    if not platform:
        if 'windows' in ua_str: platform = 'Windows'
        elif 'android' in ua_str: platform = 'Android'
        elif 'iphone' in ua_str or 'ipad' in ua_str: platform = 'iOS'
        elif 'macintosh' in ua_str or 'mac os' in ua_str: platform = 'Mac OS'
        elif 'linux' in ua_str: platform = 'Linux'
        else: platform = '未知系统'
    if not browser:
        if 'micromessenger' in ua_str: browser = 'WeChat'
        elif 'chrome' in ua_str: browser = 'Chrome'
        elif 'firefox' in ua_str: browser = 'Firefox'
        elif 'safari' in ua_str: browser = 'Safari'
        elif 'edge' in ua_str: browser = 'Edge'
        else: browser = '未知浏览器'
    device_type = "移动端" if is_mobile_device() else "PC端"
    return f"{platform} ({browser}) - {device_type}"

def _fill_ip_location(log_id, ip):
    """修复(P1-6)：后台线程查询归属地并回写日志，不再阻塞下载响应"""
    try:
        with app.app_context():
            location = get_ip_location_info(ip)
            log = db.session.get(DownloadLog, log_id)
            if log:
                log.ip_location = location
                db.session.commit()
    except Exception as e:
        app.logger.error(f"Fill IP location error: {e}")

def log_activity(filename, action):
    try:
        ip = get_real_ip()
        cutoff_time = get_beijing_time() - timedelta(seconds=30)
        recent_log = DownloadLog.query.filter(
            DownloadLog.ip_address == ip,
            DownloadLog.filename == filename,
            DownloadLog.action == action,
            DownloadLog.timestamp > cutoff_time
        ).first()

        if recent_log:
            return

        device = get_device_info()
        new_log = DownloadLog(
            filename=filename,
            ip_address=ip,
            action=action,
            ip_location='查询中',
            device_type=device
        )
        db.session.add(new_log)
        db.session.commit()
        # 修复(P1-6)：归属地查询移入后台线程
        threading.Thread(target=_fill_ip_location, args=(new_log.id, ip), daemon=True).start()
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Logging error: {e}")

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
    except Exception:
        return {'total': 'N/A', 'used': 'N/A', 'percent': 0}

def secure_path(path):
    if path is None: return ''
    path = path.strip('/')
    if '..' in path or path.startswith('/') or path.startswith('\\'):
        return None
    return path

def is_path_inside_base(full_path, base=None):
    """安全修复(P0-1/P0-2)：解析真实路径并确认最终位置仍在指定目录内，
    防止绝对路径注入与各种路径穿越变体（配合 secure_path 使用）"""
    real_base = os.path.realpath(base or BASE_DIR)
    real_path = os.path.realpath(full_path)
    return real_path == real_base or real_path.startswith(real_base + os.sep)

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

def static_versioned(filename):
    """优化(P2-4)：静态资源带文件 mtime 版本指纹，改文件后浏览器缓存自动失效"""
    try:
        fp = os.path.join(app.static_folder, filename)
        v = int(os.stat(fp).st_mtime)
        return f"{url_for('static', filename=filename)}?v={v}"
    except OSError:
        return url_for('static', filename=filename)

@app.context_processor
def inject_global_vars():
    return dict(is_admin=session.get('is_admin', False), csrf_token=get_csrf_token(),
                static_versioned=static_versioned)

# 需要校验 CSRF 的管理写操作前缀（/login、/admin/login 为登录入口，不在保护范围）
CSRF_PROTECTED_PREFIXES = ('/admin/file/', '/admin/share/', '/admin/logs/')

@app.before_request
def csrf_protect():
    """安全修复(P0-5)：管理写操作必须携带与会话绑定的 CSRF token"""
    if request.method not in ('POST', 'PUT', 'DELETE'):
        return None
    if not request.path.startswith(CSRF_PROTECTED_PREFIXES):
        return None
    session_token = session.get('csrf_token')
    if not session_token or not hmac.compare_digest(_extract_csrf_from_request(), session_token):
        return jsonify({'error': 'CSRF 校验失败，请刷新页面后重试'}), 400
    return None

# 优化(P2-5)：统一错误页与 favicon（API 请求仍返回 JSON）
def _render_error(code, message):
    if request.path.startswith('/api/'):
        return jsonify({'error': message}), code
    try:
        return render_template('error.html', code=code, message=message), code
    except Exception:
        return f"{code} {message}", code

@app.errorhandler(404)
def page_not_found(e):
    return _render_error(404, '页面不存在或文件已被移动')

@app.errorhandler(403)
def forbidden(e):
    return _render_error(403, '没有访问权限')

@app.errorhandler(410)
def gone(e):
    return _render_error(410, '该分享链接已过期')

@app.errorhandler(500)
def server_error(e):
    return _render_error(500, '服务器内部错误，请稍后重试')

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(app.static_folder, 'favicon.ico', mimetype='image/x-icon')

# ================= 接口部分 =================

# 修改：清空日志接口
# 逻辑：在删除前，统计当前表的各项数据，累加到 SystemStat 表中
@app.route('/admin/logs/clear', methods=['POST'])
def clear_logs():
    if not session.get('is_admin'): 
        return jsonify({'error': '无权操作'}), 403
    try:
        # 1. 统计当前日志中的数据
        current_downloads = DownloadLog.query.filter_by(action='down').count()
        current_views = DownloadLog.query.filter_by(action='view').count()
        current_logins = DownloadLog.query.filter(DownloadLog.action.in_(['login', 'user_login'])).count()
        
        # 2. 将数据累加到 SystemStat 表 (归档)
        update_archived_stat('total_downloads', current_downloads)
        update_archived_stat('total_views', current_views)
        update_archived_stat('total_logins', current_logins)
        
        # 3. 清空日志表
        db.session.query(DownloadLog).delete()
        db.session.commit()
        
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/admin/file/mkdir', methods=['POST'])
def create_folder():
    if not session.get('is_admin'): return jsonify({'error': '无权操作'}), 403
    # 修复(P1-8)：空/非 JSON 请求体不再导致 500
    data = request.get_json(silent=True) or {}
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
        
        full_upload_path = os.path.join(BASE_DIR, path)
        
        if not os.path.exists(full_upload_path):
            return jsonify({'error': f'目录不存在: {path}'}), 404
            
        files = request.files.getlist('files')
        saved_count = 0
        
        if not files:
            return jsonify({'error': '未接收到文件数据'}), 400
        for file in files:
            if file and file.filename:
                filename = os.path.basename(file.filename)
                filename = filename.replace('..', '').replace('/', '').replace('\\', '')
                if not filename: filename = f"upload_{int(time.time())}_{secrets.token_hex(4)}"
                
                save_path = os.path.join(full_upload_path, filename)
                
                # 处理重名
                base, ext = os.path.splitext(filename)
                counter = 1
                while os.path.exists(save_path):
                    save_path = os.path.join(full_upload_path, f"{base}_{counter}{ext}")
                    counter += 1
                
                # 手动流式写入
                chunk_size = 1024 * 1024 
                with open(save_path, 'wb') as f:
                    while True:
                        chunk = file.stream.read(chunk_size)
                        if not chunk:
                            break
                        f.write(chunk)
                
                saved_count += 1
                
        return jsonify({'success': True, 'count': saved_count})
    except Exception as e:
        error_trace = traceback.format_exc()
        # 安全修复：堆栈仅记录在服务端日志，不回传给客户端
        app.logger.error(f"Upload Failed: {str(e)}\n{error_trace}")
        return jsonify({'error': str(e)}), 500

def _sanitize_filename(raw):
    """文件名清洗：剥离路径成分与危险字符（分块上传接口专用）"""
    filename = os.path.basename(raw or '')
    filename = filename.replace('..', '').replace('/', '').replace('\\', '')
    return filename.strip()

@app.route('/admin/file/upload_check', methods=['POST'])
def upload_check():
    """配套App分块上传：查询目标文件已传偏移量（断点续传第一步）"""
    if not session.get('is_admin'): return jsonify({'error': '无权操作'}), 403
    data = request.get_json(silent=True) or {}
    path = secure_path(data.get('path', ''))
    filename = _sanitize_filename(data.get('filename', ''))
    if path is None or not filename:
        return jsonify({'error': '参数错误'}), 400
    target = os.path.join(BASE_DIR, path, filename)
    if not is_path_inside_base(target):
        return jsonify({'error': '非法路径'}), 400
    offset = os.path.getsize(target) if os.path.exists(target) else 0
    return jsonify({'success': True, 'offset': offset})

@app.route('/admin/file/upload_chunk', methods=['POST'])
def upload_chunk():
    """配套App分块上传：将分块按偏移追加写入目标文件"""
    if not session.get('is_admin'): return jsonify({'error': '无权操作'}), 403
    path = secure_path(request.form.get('path', ''))
    filename = _sanitize_filename(request.form.get('filename', ''))
    if path is None or not filename:
        return jsonify({'error': '参数错误'}), 400
    target = os.path.join(BASE_DIR, path, filename)
    if not is_path_inside_base(target):
        return jsonify({'error': '非法路径'}), 400
    try:
        offset = int(request.form.get('offset', 0))
    except (TypeError, ValueError):
        return jsonify({'error': '参数错误'}), 400
    if offset < 0:
        return jsonify({'error': '参数错误'}), 400
    chunk = request.files.get('file')
    if not chunk:
        return jsonify({'error': '未接收到分块数据'}), 400
    try:
        os.makedirs(os.path.dirname(target) or BASE_DIR, exist_ok=True)
        # 断点一致性校验：服务器现有大小必须与客户端 offset 一致，防止错位写入
        current_size = os.path.getsize(target) if os.path.exists(target) else 0
        if offset != current_size:
            return jsonify({'success': False, 'offset': current_size,
                            'error': '偏移量与服务器不一致，请从返回的偏移重新续传'}), 409
        with open(target, 'ab') as f:
            while True:
                data = chunk.stream.read(1024 * 1024)
                if not data:
                    break
                f.write(data)
        return jsonify({'success': True, 'offset': os.path.getsize(target)})
    except Exception as e:
        app.logger.error(f"Chunk upload failed: {str(e)}\n{traceback.format_exc()}")
        return jsonify({'error': str(e)}), 500

@app.route('/admin/file/rename', methods=['POST'])
def rename_item():
    if not session.get('is_admin'): return jsonify({'error': '无权操作'}), 403
    # 修复(P1-8)：空/非 JSON 请求体不再导致 500
    data = request.get_json(silent=True) or {}
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
    if not data:
        return jsonify({'error': '未解析到有效JSON数据'}), 400

    raw_path = data.get('path', '')
    path = secure_path(raw_path)
    filenames = data.get('filenames', [])

    if path is None:
        return jsonify({'error': f'非法路径: {raw_path}'}), 400

    if not filenames:
        return jsonify({'error': '未选中任何文件(filenames为空)'}), 400

    success_count = 0
    errors = []
    for name in filenames:
        if '..' in name or '/' in name or '\\' in name:
            continue
        full_path = os.path.join(BASE_DIR, path, name)
        try:
            if os.path.isfile(full_path) or os.path.islink(full_path):
                os.remove(full_path)
            elif os.path.isdir(full_path):
                shutil.rmtree(full_path)
            success_count += 1
        except Exception as e:
            app.logger.error(f"Delete failed {full_path}: {str(e)}")
            errors.append(f"{name}: {str(e)}")
            
    if errors:
        return jsonify({'success': False, 'msg': f"部分删除失败: {'; '.join(errors)}"})
    return jsonify({'success': True})

def _safe_next_url(target):
    """安全修复：仅允许站内相对路径，防止 open redirect"""
    if target and target.startswith('/') and not target.startswith('//') and '\\' not in target:
        return target
    return url_for('index')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        client_ip = get_real_ip()
        locked = login_guard.is_locked(client_ip)
        if locked:
            flash(f'尝试过于频繁，请 {locked} 秒后再试', 'error')
            return render_template('login.html', title="安全访问验证", subtitle="请输入访问口令以继续"), 429
        input_pwd = request.form.get('password', '').strip().encode('utf-8')
        stored_pwd = get_config()['user_password'].encode('utf-8')
        if hmac.compare_digest(input_pwd, stored_pwd):
            login_guard.record_success(client_ip)
            session['is_verified'] = True
            session.permanent = True  # 优化(P2-9)：7 天免登录
            log_activity('普通用户登录', 'user_login')
            return redirect(_safe_next_url(request.args.get('next')))
        else:
            login_guard.record_failure(client_ip)
            time.sleep(1); flash('访问口令错误', 'error')
    return render_template('login.html', title="安全访问验证", subtitle="请输入访问口令以继续")

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if session.get('is_admin'): return redirect(url_for('admin_dashboard'))
    if request.method == 'POST':
        client_ip = get_real_ip()
        locked = login_guard.is_locked(client_ip)
        if locked:
            flash(f'尝试过于频繁，请 {locked} 秒后再试', 'error')
            return render_template('login.html', title="管理后台验证", subtitle="请输入管理员口令"), 429
        input_pwd = request.form.get('password', '').strip().encode('utf-8')
        stored_pwd = get_config()['admin_password'].encode('utf-8')
        if hmac.compare_digest(input_pwd, stored_pwd):
            login_guard.record_success(client_ip)
            session['is_admin'] = True
            session.permanent = True  # 优化(P2-9)：7 天免登录
            log_activity('管理员后台登录', 'admin_login')
            return redirect(url_for('admin_dashboard'))
        else:
            login_guard.record_failure(client_ip)
            flash('管理员口令错误', 'error')
    return render_template('login.html', title="管理后台验证", subtitle="请输入管理员口令")

@app.route('/logout')
def logout():
    if session.get('is_admin'):
        log_activity('管理员退出', 'logout')
    elif session.get('is_verified'):
        log_activity('用户退出', 'logout')
        
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
    now = get_beijing_time()
    for s in shares: s.is_expired = s.expire_at and s.expire_at < now
    
    # 统计算法
    current_downloads = DownloadLog.query.filter_by(action='down').count()
    archived_downloads = get_archived_stat('total_downloads')
    
    current_views = DownloadLog.query.filter_by(action='view').count()
    archived_views = get_archived_stat('total_views')
    
    current_logins = DownloadLog.query.filter(DownloadLog.action.in_(['login', 'user_login'])).count()
    archived_logins = get_archived_stat('total_logins')

    stats = {
        'total_downloads': current_downloads + archived_downloads,
        'total_views': current_views + archived_views,
        'total_logins': current_logins + archived_logins,
        'disk': get_disk_usage()
    }
    
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
    # 安全修复(P0-2)：file_path 必须是共享目录内的相对路径，禁止绝对路径注入与路径穿越
    file_path = secure_path(data.get('file_path', ''))
    if not file_path or not is_path_inside_base(os.path.join(BASE_DIR, file_path)):
        msg = '非法文件路径'
        if request.is_json: return jsonify({'error': msg}), 400
        flash(msg, 'error')
        return redirect(url_for('admin_dashboard'))
    file_path = file_path.replace('\\', '/')
    slug = data.get('slug', '').strip()
    # 安全修复：自定义后缀白名单，避免生成不可访问或异常的链接
    if slug and not re.fullmatch(r'[A-Za-z0-9_-]{1,50}', slug):
        msg = '后缀仅允许字母、数字、下划线和短横线（1-50位）'
        if request.is_json: return jsonify({'error': msg}), 400
        flash(msg, 'error')
        return redirect(url_for('admin_dashboard'))
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
        try:
            expire_at = get_beijing_time() + timedelta(days=int(duration))
        except Exception:
            pass
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
            try:
                share.expire_at = get_beijing_time() + timedelta(days=int(duration))
            except Exception:
                pass
    db.session.commit()
    flash('分享链接已更新', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/share/delete/<int:id>', methods=['POST'])
def delete_share(id):
    if not session.get('is_admin'):
        if 'application/json' in request.headers.get('Accept', ''): return jsonify({'error': '无权操作'}), 403
        abort(403)
    share = FileShare.query.get_or_404(id)
    db.session.delete(share); db.session.commit()
    # 安全修复(P0-5)：删除操作由 GET 改为 POST，杜绝链接预取/CSRF 直接触发
    if 'application/json' in request.headers.get('Accept', ''):
        return jsonify({'success': True})
    flash('分享链接已删除', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/', defaults={'req_path': ''})
@app.route('/<path:req_path>')
def index(req_path):
    if req_path and '..' not in req_path:
        share = FileShare.query.filter_by(slug=req_path).first()
        if share:
            if share.expire_at and share.expire_at < get_beijing_time(): abort(410)
            full_path = os.path.join(BASE_DIR, share.file_path)
            # 安全修复(P0-2)：防止历史脏数据或越界路径外泄共享目录以外的文件
            if not is_path_inside_base(full_path): abort(403)
            if not os.path.exists(full_path): abort(404)
            share.downloads += 1
            # 修复(P1-5)：计数显式提交，不再依赖 log_activity 内部的 commit（去重命中/异常时不再丢计数）
            try:
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Share count commit error: {e}")
            log_activity(f"[Share] {share.file_path}", 'share_down')
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
                            raw_html = markdown.markdown(f.read(), extensions=['fenced_code', 'tables'])
                            # 安全修复(P1-2)：白名单消毒后再输出，防止 readme 内嵌脚本/事件属性
                            readme_content = bleach.clean(
                                raw_html,
                                tags=['h1','h2','h3','h4','h5','h6','p','a','b','strong','i','em','u','s',
                                      'blockquote','ul','ol','li','code','pre','table','thead','tbody','tr','th','td',
                                      'img','br','hr','span','div','sup','sub'],
                                attributes={'a': ['href','title','target','rel'],
                                            'img': ['src','alt','title','width','height'],
                                            '*': ['class','id']},
                                protocols=['http','https','mailto']
                            )
                    except Exception as e:
                        app.logger.warning(f"Readme load error: {e}")
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
        # 优化(P2-3)：超过 8 层深度不再下钻，防止超大目录树拖慢搜索
        if root[len(BASE_DIR):].count(os.sep) >= 8:
            dirs[:] = []
            continue
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
    # 安全修复：解析真实路径并确认仍在共享目录内（防绝对路径/穿越变体）
    if not is_path_inside_base(full_path): abort(403)
    try:
        log_activity(req_path, 'down' if as_attachment else 'view')
    except Exception:
        pass
    return send_from_directory(os.path.dirname(full_path), os.path.basename(full_path), as_attachment=as_attachment)

from api_mobile import init_mobile_api
init_mobile_api(app, BASE_DIR, get_config, get_file_type, human_readable_size,
                db, DownloadLog, SystemStat, FileShare, get_disk_usage, get_archived_stat,
                login_guard=login_guard, log_activity_func=log_activity,
                get_csrf_token_func=get_csrf_token)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9711)