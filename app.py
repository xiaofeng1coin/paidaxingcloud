import json
import os
import re
import shutil
import hashlib
import hmac
import threading
import ipaddress
import markdown
import nh3
import time
import secrets
import logging
import sys
import requests
import traceback
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
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

# 安全修复(H1)：可信代理配置——默认 "*" 与历史部署保持兼容（信任 XFF/CF 头）；
# 直连部署时设置环境变量收紧，例如 NEXUS_TRUSTED_PROXIES="10.0.0.0/8,192.168.0.0/16"，
# 留空则完全不信任转发头（一律使用直连来源 IP）
_raw_proxies = os.environ.get('NEXUS_TRUSTED_PROXIES', '*').strip()
TRUST_ALL_PROXIES = _raw_proxies == '*'
TRUSTED_PROXY_NETS = []
if not TRUST_ALL_PROXIES and _raw_proxies:
    for _part in _raw_proxies.split(','):
        _part = _part.strip()
        if _part:
            try:
                TRUSTED_PROXY_NETS.append(ipaddress.ip_network(_part, strict=False))
            except ValueError:
                pass

def _remote_addr_trusted():
    """判断直连来源是否属于可信代理"""
    if TRUST_ALL_PROXIES:
        return True
    try:
        ip = ipaddress.ip_address(request.remote_addr or '')
    except ValueError:
        return False
    return any(ip in net for net in TRUSTED_PROXY_NETS)

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
        # 修复(L8)：密钥文件收紧权限（Linux 下 600；Windows 上仅影响只读位，不报错）
        try:
            os.chmod(secret_file, 0o600)
        except Exception:
            pass
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
    """获取北京时间 (UTC+8)。
    修复(L6)：datetime.now(timezone.utc) 替代 3.12+ 已弃用的 utcnow；
    保持 naive 值以兼容 SQLite 存储与既有比较逻辑"""
    return datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=8)

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
    # 优化(O1)：为日志去重查询与时间排序建立索引
    __table_args__ = (
        db.Index('idx_log_dedup', 'ip_address', 'filename', 'action', 'timestamp'),
        db.Index('idx_log_timestamp', 'timestamp'),
    )
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

        # 优化(O1)：为存量数据库补建索引（SQLite 支持 IF NOT EXISTS）
        try:
            with db.engine.connect() as conn:
                conn.execute(text("CREATE INDEX IF NOT EXISTS idx_log_dedup ON download_log (ip_address, filename, action, timestamp)"))
                conn.execute(text("CREATE INDEX IF NOT EXISTS idx_log_timestamp ON download_log (timestamp)"))
                conn.commit()
        except Exception as e: app.logger.error(f"DB Index Error: {e}")

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
    """内存级登录防爆破：同一来源连续失败达到上限后锁定一段时间；
    安全修复(H1)：新增全局失败统计与惰性清理，防伪造海量 IP 绕过单 IP 锁定。
    复审调整(10.4.1)：全局兜底不再预拒绝请求（避免攻击者故意触发全局锁误伤正常用户），
    仅在失败响应中提示全局保护状态；口令验证本身很轻量，不构成 DoS 面"""
    def __init__(self, max_attempts=5, lock_seconds=600,
                 global_max=50, global_window=600, global_lock=180, max_records=5000):
        self.max_attempts = max_attempts
        self.lock_seconds = lock_seconds
        self.records = {}
        self.max_records = max_records
        self.global_max = global_max          # 全局窗口内允许的最大失败次数（触发保护提示）
        self.global_window = global_window    # 全局统计窗口（秒）
        self.global_lock = global_lock        # 全局保护提示持续时长（秒）
        self.global_count = 0
        self.global_window_start = time.time()
        self.global_locked_until = 0

    def _sweep(self):
        """惰性清理：控制记录容量，滚动全局统计窗口"""
        now = time.time()
        if len(self.records) > self.max_records:
            for ip in list(self.records.keys())[:len(self.records) - self.max_records]:
                rec = self.records.get(ip)
                if not rec or not rec.get('locked_until') or rec['locked_until'] < now:
                    self.records.pop(ip, None)
        if now - self.global_window_start >= self.global_window:
            self.global_count = 0
            self.global_window_start = now

    def global_locked(self):
        """全局保护状态：短窗口内总失败次数过大时返回剩余秒数（仅用于失败提示，不预拒绝）"""
        self._sweep()
        if self.global_locked_until and time.time() < self.global_locked_until:
            return int(self.global_locked_until - time.time()) + 1
        return 0

    def is_locked(self, ip):
        """返回该 IP 剩余锁定秒数（仅单 IP 锁定，全局保护不影响正确口令登录），未锁定返回 0"""
        self._sweep()
        rec = self.records.get(ip)
        if rec:
            locked_until = rec.get('locked_until', 0)
            if locked_until and time.time() < locked_until:
                return int(locked_until - time.time()) + 1
        return 0

    def record_failure(self, ip):
        self._sweep()
        self.global_count += 1
        if self.global_count >= self.global_max:
            self.global_locked_until = time.time() + self.global_lock
            self.global_count = 0
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
    """安全修复(H1)：仅当直连来源属于可信代理时才解析转发头，否则一律使用 remote_addr"""
    if _remote_addr_trusted():
        if 'CF-Connecting-IP' in request.headers:
            return request.headers.get('CF-Connecting-IP')
        if 'X-Forwarded-For' in request.headers:
            return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr

# 修复(P1-6)：IP 归属地进程内缓存，避免同一 IP 反复请求外部接口
IP_LOCATION_CACHE = {}
IP_LOCATION_CACHE_MAX = 2000
IP_LOCATION_TTL = 24 * 3600  # 24 小时

def _is_private_ip(ip):
    """修复(L1)：使用 ipaddress 精确判断私网段（含 IPv6），替代 startswith 误判"""
    if ip in ('127.0.0.1', 'localhost', '::1', '0.0.0.0'):
        return True
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

def get_ip_location_info(ip):
    # 优化(O8)：可通过环境变量 NEXUS_DISABLE_IP_LOCATION=1 关闭归属地查询（隐私考虑）
    if os.environ.get('NEXUS_DISABLE_IP_LOCATION', '').strip().lower() in ('1', 'true', 'yes', 'on'):
        return "未知"
    if _is_private_ip(ip):
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

# 优化(O4)：归属地回写使用固定线程池，防止突发流量时线程失控
_ip_location_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix='iploc')

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
    finally:
        # 修复(O4)残留：显式释放线程内会话，避免连接/会话残留
        db.session.remove()

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
        # 修复(P1-6)+优化(O4)：归属地查询移入后台固定线程池（防突发流量线程失控）
        _ip_location_pool.submit(_fill_ip_location, new_log.id, ip)
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Logging error: {e}")

def human_readable_size(size):
    # 修复(L2)：单位表覆盖到 PB，超大容量不再错误显示为 TB
    for unit in ['B', 'KB', 'MB', 'GB', 'TB', 'PB']:
        if size < 1024: return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"

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
    # 安全修复(M3)：拦截 Windows 盘符形态（如 C:/x），保证与部署平台无关
    if re.match(r'^[A-Za-z]:', path):
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
# 安全修复(N6)：/logout 纳入 CSRF 保护（登出请求三端均需携带会话令牌）
CSRF_PROTECTED_PREFIXES = ('/admin/file/', '/admin/share/', '/admin/logs/', '/logout')

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

# 安全修复(M7)：全站基础安全响应头
@app.after_request
def add_security_headers(resp):
    # SAMEORIGIN 而非 DENY：站内文档预览（PDF 等）依赖同源 iframe，外站嵌套仍被拦截
    resp.headers['X-Frame-Options'] = 'SAMEORIGIN'
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['Referrer-Policy'] = 'same-origin'
    return resp

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
    # 安全修复(M3)：落地路径 realpath 兜底，防止共享目录内符号链接越界
    if not is_path_inside_base(full_path):
        return jsonify({'error': '非法路径'}), 400
    try:
        os.makedirs(full_path, exist_ok=False)
        _search_cache['ts'] = 0.0  # 自查修复(S5)：写操作后失效搜索缓存，避免结果滞后
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
        # 安全修复(M3)：落地路径 realpath 兜底
        if not is_path_inside_base(full_upload_path):
            return jsonify({'error': '非法路径'}), 400

        if not os.path.exists(full_upload_path):
            return jsonify({'error': f'目录不存在: {path}'}), 404

        files = request.files.getlist('files')
        saved_count = 0

        if not files:
            return jsonify({'error': '未接收到文件数据'}), 400
        for file in files:
            if file and file.filename:
                # 安全修复(M5)复审补充：多文件上传逐个文件写入前检查磁盘水位
                try:
                    if shutil.disk_usage(BASE_DIR).free < 1024 * 1024 * 1024:
                        return jsonify({'error': '服务器磁盘空间不足，上传已拒绝'}), 507
                except Exception:
                    pass
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

        if saved_count:
            _search_cache['ts'] = 0.0  # 自查修复(S5)：上传后失效搜索缓存
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

# 优化(O7)：分块追加写入的全局互斥锁（一致性校验与写入原子化）
_chunk_write_lock = threading.Lock()

@app.route('/admin/file/upload_check', methods=['POST'])
def upload_check():
    """配套App分块上传：查询目标文件已传偏移量（断点续传第一步）。
    两阶段协议(修复 N7)：
      第一次（无 md5）：返回远端当前大小 offset；
      第二次（带 md5）：客户端计算"本地前 offset 字节"的前缀哈希，服务端比对远端残留哈希——
        一致 → 从该偏移续传（offset == 文件总长时等价秒传）；
        不一致 → 服务端【先清理残留】再返回 offset=0，使"从零重传"真正可行
      （残留文件的哈希不可能等于完整文件的哈希，mismatch 后不清残留会导致 chunk 409 死锁）"""
    if not session.get('is_admin'): return jsonify({'error': '无权操作'}), 403
    data = request.get_json(silent=True) or {}
    path = secure_path(data.get('path', ''))
    filename = _sanitize_filename(data.get('filename', ''))
    if path is None or not filename:
        return jsonify({'error': '参数错误'}), 400
    target = os.path.join(BASE_DIR, path, filename)
    if not is_path_inside_base(target):
        return jsonify({'error': '非法路径'}), 400
    client_md5 = (data.get('md5') or '').strip().lower()
    offset_now = os.path.getsize(target) if os.path.exists(target) else 0
    if offset_now > 0 and client_md5:
        try:
            h = hashlib.md5()
            with open(target, 'rb') as f:
                for blk in iter(lambda: f.read(1024 * 1024), b''):
                    h.update(blk)
            if h.hexdigest() == client_md5:
                # 前缀哈希一致 → 从该偏移续传（等价秒传）
                return jsonify({'success': True, 'offset': offset_now, 'verified': True})
            # N7 修复：残留内容与客户端前缀不一致 → 先清理残留再返回 offset=0
            try:
                os.remove(target)
            except OSError:
                pass
            return jsonify({'success': True, 'offset': 0, 'mismatch': True})
        except Exception as e:
            app.logger.error(f"Upload check md5 error: {e}")
    return jsonify({'success': True, 'offset': offset_now})

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
        # 安全修复(M5)：写入前检查磁盘剩余水位（预留 1GB）
        if shutil.disk_usage(BASE_DIR).free < 1024 * 1024 * 1024:
            return jsonify({'error': '服务器磁盘空间不足，上传已拒绝'}), 507
        os.makedirs(os.path.dirname(target) or BASE_DIR, exist_ok=True)
        # 优化(O7)：一致性校验与追加写入整体持锁，消除并发竞态
        with _chunk_write_lock:
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
        _search_cache['ts'] = 0.0  # 自查修复(S5)：分块写入后失效搜索缓存
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
    # 安全修复(H2)：old_name 与 new_name 同等校验，且两个落地路径都必须在共享目录内
    if '..' in old_name or '/' in old_name or '\\' in old_name: return jsonify({'error': '原名称非法'}), 400
    old_path = os.path.join(BASE_DIR, path, old_name)
    new_path = os.path.join(BASE_DIR, path, new_name)
    if not is_path_inside_base(old_path) or not is_path_inside_base(new_path):
        return jsonify({'error': '非法路径'}), 400
    if not os.path.exists(old_path): return jsonify({'error': '原文件不存在'}), 404
    if os.path.exists(new_path): return jsonify({'error': '新名称已存在'}), 400
    try:
        os.rename(old_path, new_path)
        _search_cache['ts'] = 0.0  # 自查修复(S5)：重命名后失效搜索缓存
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/admin/file/delete', methods=['POST'])
def delete_items():
    if not session.get('is_admin'): return jsonify({'error': '无权操作'}), 403

    data = request.get_json(silent=True) or {}
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
        # 安全修复(M3)残留：删除落地路径 realpath 兜底，防符号链接目录越界删除
        if not is_path_inside_base(full_path):
            errors.append(f"{name}: 非法路径")
            continue
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
    _search_cache['ts'] = 0.0  # 自查修复(S5)：删除后失效搜索缓存
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
            # 安全修复(M4)：移除同步 sleep，拖延交给 LoginGuard 锁定机制
            # 复审调整(10.4.1)：全局保护触发时失败提示区分（正确口令永不被全局兜底拦截）
            if login_guard.global_locked():
                flash('尝试过于频繁（全局保护已触发），请稍后再试', 'error')
            else:
                flash('访问口令错误', 'error')
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
            session['is_verified'] = True  # 修复(L7)：管理员浏览文件无需再输用户口令
            session.permanent = True  # 优化(P2-9)：7 天免登录
            log_activity('管理员后台登录', 'admin_login')
            return redirect(url_for('admin_dashboard'))
        else:
            login_guard.record_failure(client_ip)
            if login_guard.global_locked():
                flash('尝试过于频繁（全局保护已触发），请稍后再试', 'error')
            else:
                flash('管理员口令错误', 'error')
    return render_template('login.html', title="管理后台验证", subtitle="请输入管理员口令")

@app.route('/logout', methods=['POST'])
def logout():
    # 安全修复(L10)：登出由 GET 改为 POST，防止链接预取/预取器误触登出
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
    
    # 优化(O6)：限制单页分享数量，防止分享量大时拖慢后台
    shares = FileShare.query.order_by(FileShare.created_at.desc()).limit(500).all()
    now = get_beijing_time()
    for s in shares: s.is_expired = s.expire_at and s.expire_at < now
    
    # 统计算法（优化 O2：合并为一条 GROUP BY 查询）
    action_counts = dict(
        db.session.query(DownloadLog.action, db.func.count(DownloadLog.id))
        .group_by(DownloadLog.action).all()
    )
    current_downloads = action_counts.get('down', 0)
    current_views = action_counts.get('view', 0)
    current_logins = action_counts.get('login', 0) + action_counts.get('user_login', 0)
    archived_downloads = get_archived_stat('total_downloads')
    archived_views = get_archived_stat('total_views')
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
    # 安全修复(M6)：设置 NEXUS_PUBLIC_BASE_URL（如 https://domain.com）后，
    # 分享外链固定为该地址，不再依赖请求 Host 头，杜绝 Host 注入污染外链
    public_base = os.environ.get('NEXUS_PUBLIC_BASE_URL', '').strip().rstrip('/')
    if public_base:
        share_url = f"{public_base}/{slug}"
    else:
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
    # 安全修复(M1)：编辑分享补上与创建相同的 slug 白名单校验，防止存储型 XSS
    if not slug or not re.fullmatch(r'[A-Za-z0-9_-]{1,50}', slug):
        flash('修改失败：后缀仅允许字母、数字、下划线和短横线（1-50位）', 'error')
        return redirect(url_for('admin_dashboard'))
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
            # 修复(P1-5/L9)：改为原子 UPDATE + 显式提交，并发下不再丢计数
            try:
                db.session.execute(text("UPDATE file_share SET downloads = downloads + 1 WHERE id = :sid"),
                                   {'sid': share.id})
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
    # 安全修复(M3)：目录列表落地路径 realpath 兜底
    if not is_path_inside_base(full_path): abort(403)
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
                            # 安全修复(P1-2/H4)：白名单消毒（nh3 替代已停止维护的 bleach）
                            # 注意：nh3/ammonia 自动管理 <a> 的 rel 属性（自动追加 noopener），
                            # attributes 中手动指定 rel 会触发底层断言崩溃，故不包含 rel
                            readme_content = nh3.clean(
                                raw_html,
                                tags={'h1','h2','h3','h4','h5','h6','p','a','b','strong','i','em','u','s',
                                      'blockquote','ul','ol','li','code','pre','table','thead','tbody','tr','th','td',
                                      'img','br','hr','span','div','sup','sub'},
                                attributes={'a': {'href','title','target'},
                                            'img': {'src','alt','title','width','height'},
                                            '*': {'class','id'}},
                                url_schemes={'http','https','mailto'},
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

# 优化(O3)：目录索引缓存（60 秒 TTL），搜索时内存过滤，避免每次全盘 walk
_search_cache = {'items': None, 'ts': 0.0}

def _build_search_index():
    items = []
    for root, dirs, files in os.walk(BASE_DIR):
        dirs[:] = [d for d in dirs if not d.startswith('.')]
        # 优化(P2-3)：超过 8 层深度不再下钻，防止超大目录树拖慢搜索
        if root[len(BASE_DIR):].count(os.sep) >= 8:
            dirs[:] = []
            continue
        for name in files:
            try:
                full_path = os.path.join(root, name)
                rel = os.path.relpath(full_path, BASE_DIR).replace('\\', '/')
                items.append({'name': name, 'is_dir': False, 'size': os.path.getsize(full_path), 'rel_path': rel})
            except OSError:
                continue
        for name in dirs:
            rel = os.path.relpath(os.path.join(root, name), BASE_DIR).replace('\\', '/')
            items.append({'name': name, 'is_dir': True, 'size': 0, 'rel_path': rel})
    return items

@app.route('/api/search')
def search():
    if not session.get('is_verified'): return jsonify([])
    query = request.args.get('q', '').lower()
    if not query: return jsonify([])
    now = time.time()
    if _search_cache['items'] is None or now - _search_cache['ts'] > 60:
        try:
            _search_cache['items'] = _build_search_index()
            _search_cache['ts'] = now
        except Exception as e:
            app.logger.error(f"Search index error: {e}")
    results = []
    for entry in (_search_cache['items'] or []):
        if query in entry['name'].lower():
            is_dir = entry['is_dir']
            results.append({
                'name': entry['name'], 'is_dir': is_dir,
                'type': 'folder' if is_dir else get_file_type(entry['name']),
                'rel_path': entry['rel_path'],
                'size': human_readable_size(entry['size']) if not is_dir else '-'
            })
            if len(results) >= 30: break
    return jsonify(results)

@app.route('/download/<path:req_path>')
def download(req_path): 
    if not session.get('is_verified'): return redirect(url_for('login'))
    return serve_file(req_path, True)

@app.route('/view/<path:req_path>')
def view(req_path):
    if not session.get('is_verified'): return redirect(url_for('login'))
    # 安全修复(M2)：可承载脚本的类型禁止同源内联渲染，一律转为下载
    # 复审补充：黑名单补全 .shtml/.xht/.svgz/.hta
    ext = os.path.splitext(req_path)[1].lower()
    if ext in ('.html', '.htm', '.xhtml', '.xht', '.shtml', '.svg', '.svgz', '.xml', '.swf', '.hta'):
        return serve_file(req_path, True)
    return serve_file(req_path, False)

def serve_file(req_path, as_attachment):
    if '..' in req_path: abort(403)
    full_path = os.path.join(BASE_DIR, req_path)
    # 安全修复：解析真实路径并确认仍在共享目录内（防绝对路径/穿越变体）
    if not is_path_inside_base(full_path): abort(403)
    try:
        if request.method != 'HEAD':
            # 自查修复(S4)：App 多线程下载的 HEAD 探测不计入下载日志
            log_activity(req_path, 'down' if as_attachment else 'view')
    except Exception:
        pass
    return send_from_directory(os.path.dirname(full_path), os.path.basename(full_path), as_attachment=as_attachment)

from api_mobile import init_mobile_api
init_mobile_api(app, BASE_DIR, get_config, get_file_type, human_readable_size,
                db, DownloadLog, SystemStat, FileShare, get_disk_usage, get_archived_stat,
                login_guard=login_guard, log_activity_func=log_activity,
                get_csrf_token_func=get_csrf_token, get_real_ip_func=get_real_ip)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9711)