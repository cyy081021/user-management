"""
认证模块 — 登录逻辑（使用 SQLite users 表）
"""
import logging
from flask import request
from app.security import record_login_failure, get_login_delay, clear_login_failures, anti_enumeration_delay
from app.users import verify_password, get_user_by_username

logger = logging.getLogger(__name__)


def _get_client_ip():
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded and forwarded.strip():
        return forwarded.strip().split(",")[0].strip()
    return request.remote_addr or ""


def perform_login(username, password):
    """
    执行登录，返回 (成功?, 用户信息或错误信息)
    """
    ip = _get_client_ip()
    delay = get_login_delay(username, ip)
    anti_enumeration_delay(delay)

    if verify_password(username, password):
        clear_login_failures(username, ip)
        user = get_user_by_username(username)
        logger.info("用户 '%s' 登录成功 (ip=%s)", username, ip)
        return True, user

    next_delay = record_login_failure(username, ip)
    logger.info("登录失败: user=%s ip=%s next_delay=%.1fs", username, ip, next_delay)
    return False, "用户名或密码错误"
