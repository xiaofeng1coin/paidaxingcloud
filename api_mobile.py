from flask import Blueprint, request, jsonify, session
import os
import secrets
from datetime import datetime, timedelta

api_bp = Blueprint('api_mobile', __name__, url_prefix='/api/mobile')


def _get_client_ip():
    """获取客户端真实 IP（与主站 get_real_ip 逻辑一致）"""
    if 'CF-Connecting-IP' in request.headers:
        return request.headers.get('CF-Connecting-IP')
    if 'X-Forwarded-For' in request.headers:
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr


def _get_beijing_time():
    """修复(P1-4)：北京时间 (UTC+8)，与主站 get_beijing_time 保持一致"""
    return datetime.utcnow() + timedelta(hours=8)


def _safe_resolve(base_dir, req_path):
    """安全修复(P0-1)：解析请求路径并确认仍在 base_dir 内，防目录穿越；越界返回 None"""
    full_path = os.path.join(base_dir, req_path)
    real_base = os.path.realpath(base_dir)
    real_path = os.path.realpath(full_path)
    if real_path == real_base or real_path.startswith(real_base + os.sep):
        return real_path
    return None


def init_mobile_api(app, base_dir, get_config_func, get_file_type_func, human_size_func,
                    db, DownloadLog, SystemStat, FileShare, get_disk_usage_func, get_archived_stat_func,
                    login_guard=None, log_activity_func=None, get_csrf_token_func=None):

    @api_bp.route('/login', methods=['POST'])
    def mobile_login():
        # 安全修复：request.json 判空，避免非 JSON 请求导致 500
        data = request.get_json(silent=True) or {}
        password = data.get('password', '')
        is_admin_login = bool(data.get('is_admin', False))
        client_ip = _get_client_ip()

        # 安全修复(P0-4)：接入登录防爆破（与主站共用同一份失败记录）
        if login_guard:
            locked = login_guard.is_locked(client_ip)
            if locked:
                return jsonify({'success': False, 'error': f'尝试过于频繁，请 {locked} 秒后再试'}), 429

        config = get_config_func()
        if is_admin_login:
            if secrets.compare_digest(password.encode('utf-8'), config['admin_password'].encode('utf-8')):
                if login_guard: login_guard.record_success(client_ip)
                session['is_admin'] = True
                session.permanent = True  # 优化(P2-9)：7 天免登录
                # 安全修复(P0-4)：移动端登录也写入日志，便于审计
                if log_activity_func: log_activity_func('移动端管理员登录', 'admin_login')
                return jsonify({'success': True, 'role': 'admin'})
        else:
            if secrets.compare_digest(password.encode('utf-8'), config['user_password'].encode('utf-8')):
                if login_guard: login_guard.record_success(client_ip)
                session['is_verified'] = True
                session.permanent = True  # 优化(P2-9)：7 天免登录
                if log_activity_func: log_activity_func('移动端用户登录', 'user_login')
                return jsonify({'success': True, 'role': 'user'})
        if login_guard: login_guard.record_failure(client_ip)
        return jsonify({'success': False, 'error': '口令错误'}), 401

    @api_bp.route('/csrf')
    def mobile_csrf():
        """配套App：登录后获取当前会话的 CSRF token（写操作时经 X-CSRF-Token 头携带）"""
        if not session.get('is_verified') and not session.get('is_admin'):
            return jsonify({'error': '未登录'}), 401
        if not get_csrf_token_func:
            return jsonify({'error': '未启用'}), 500
        return jsonify({'success': True, 'csrf_token': get_csrf_token_func()})

    @api_bp.route('/list', defaults={'req_path': ''})
    @api_bp.route('/list/<path:req_path>')
    def mobile_list(req_path):
        if not session.get('is_verified') and not session.get('is_admin'):
            return jsonify({'error': '未登录'}), 401
        # 安全修复(P0-1)：路径穿越防护，拒绝 '..' 与越界访问
        if '..' in req_path:
            return jsonify({'error': '非法路径'}), 400
        full_path = _safe_resolve(base_dir, req_path)
        if full_path is None:
            return jsonify({'error': '非法路径'}), 400
        if not os.path.exists(full_path): return jsonify({'error': '路径不存在'}), 404
        items = []
        try:
            with os.scandir(full_path) as it:
                for entry in it:
                    if entry.name.startswith('.'): continue
                    is_dir = entry.is_dir()
                    stat = entry.stat()
                    items.append({
                        'name': entry.name, 'is_dir': is_dir,
                        'type': 'folder' if is_dir else get_file_type_func(entry.name),
                        'size': human_size_func(stat.st_size) if not is_dir else '-',
                        'mtime': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M'),
                        'rel_path': os.path.join(req_path, entry.name).replace('\\', '/').strip('/')
                    })
        except Exception as e: return jsonify({'error': str(e)}), 500
        return jsonify({'success': True, 'items': items})

    @api_bp.route('/admin/dashboard')
    def mobile_dashboard():
        if not session.get('is_admin'): return jsonify({'error': '无权操作'}), 403

        current_downloads = DownloadLog.query.filter_by(action='down').count()
        archived_downloads = get_archived_stat_func('total_downloads')
        current_views = DownloadLog.query.filter_by(action='view').count()
        archived_views = get_archived_stat_func('total_views')
        current_logins = DownloadLog.query.filter(DownloadLog.action.in_(['login', 'user_login'])).count()
        archived_logins = get_archived_stat_func('total_logins')

        shares = FileShare.query.order_by(FileShare.created_at.desc()).all()
        share_list = []
        now = _get_beijing_time()  # 修复(P1-4)：与存储的北京时间一致，过期判定不再延后 8 小时
        for s in shares:
            share_list.append({
                'id': s.id, 'file_path': s.file_path, 'slug': s.slug,
                'downloads': s.downloads, 'is_expired': bool(s.expire_at and s.expire_at < now),
                'created_at': s.created_at.strftime('%Y-%m-%d %H:%M')
            })

        # 新增：查询最新 100 条系统日志供 App 使用
        logs = DownloadLog.query.order_by(DownloadLog.timestamp.desc()).limit(100).all()
        log_list = []
        for l in logs:
            log_list.append({
                'id': l.id,
                'filename': l.filename,
                'ip_address': l.ip_address,
                'action': l.action,
                'ip_location': l.ip_location,
                'device_type': l.device_type,
                'timestamp': l.timestamp.strftime('%m-%d %H:%M')
            })

        return jsonify({
            'success': True,
            'stats': {
                'downloads': current_downloads + archived_downloads,
                'views': current_views + archived_views,
                'logins': current_logins + archived_logins,
                'disk': get_disk_usage_func()
            },
            'shares': share_list,
            'logs': log_list  # 新增的日志数组
        })

    app.register_blueprint(api_bp)
