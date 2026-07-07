"""
认证模块 — 登录/登出业务逻辑
"""
import logging

from app.security import (
    record_login_failure,
    is_account_locked,
    get_lockout_ttl,
    clear_login_failures,
    anti_enumeration_delay,
)
from app.users import verify_password, get_safe_user_info

logger = logging.getLogger(__name__)


def perform_login(username, password):
    """
    执行登录，返回 (成功?, 用户信息或错误信息)
    """
    anti_enumeration_delay()

    # 检查账号锁定
    if is_account_locked(username):
        ttl = get_lockout_ttl(username)
        logger.warning("账号 '%s' 已锁定（剩余 %ds）", username, ttl)
        return False, f"账号已被临时锁定，请 {ttl} 秒后再试"

    # 验证密码
    if verify_password(username, password):
        clear_login_failures(username)
        logger.info("用户 '%s' 登录成功", username)
        return True, get_safe_user_info(username)

    # 失败处理
    attempts = record_login_failure(username)
    logger.info("用户 '%s' 登录失败（第 %d 次）", username, attempts)
    return False, "用户名或密码错误"
