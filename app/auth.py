"""
认证模块 — 登录/登出业务逻辑

使用基于 IP+用户名的渐进延迟，不暴露硬锁定状态。
"""
import logging

from flask import request

from app.security import (
    record_login_failure,
    get_login_delay,
    clear_login_failures,
    anti_enumeration_delay,
)
from app.users import verify_password, get_safe_user_info

logger = logging.getLogger(__name__)


def _get_client_ip():
    """尝试从请求头获取真实 IP（兼容反代）"""
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded and forwarded.strip():
        return forwarded.strip().split(",")[0].strip()
    return request.remote_addr or ""


def perform_login(username, password):
    """
    执行登录，返回 (成功?, 用户信息或错误信息)

    不使用硬锁定——错误次数多只增加延迟，攻击者无法区分"账号存在但被锁"和"账号不存在"。
    """
    ip = _get_client_ip()

    # 1. 读取当前延迟并等待（不递增计数）
    delay = get_login_delay(username, ip)
    anti_enumeration_delay(delay)

    # 2. 验证密码
    if verify_password(username, password):
        clear_login_failures(username, ip)
        logger.info("用户 '%s' 登录成功 (ip=%s)", username, ip)
        return True, get_safe_user_info(username)

    # 3. 失败 → 记录并获取下一次应等待的延迟
    next_delay = record_login_failure(username, ip)
    logger.info("登录失败: user=%s ip=%s next_delay=%.1fs", username, ip, next_delay)
    return False, "用户名或密码错误"
