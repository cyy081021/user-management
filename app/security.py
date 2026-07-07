"""
安全工具模块 — 密码校验、环境变量检查、Redis 连接、安全响应头
"""
import os
import sys
import re
import time
import random
import logging

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------
PASSWORD_MIN_LENGTH = 12
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = 900  # 15 分钟
PLACEHOLDER_PATTERNS = [
    "在此处填写", "your_", "placeholder", "changeme",
    "change_me", "passw0rd", "123456", "qwerty",
]

_redis = None  # lazy init


# ---------------------------------------------------------------------------
# 密码强度
# ---------------------------------------------------------------------------
def _check_password_strength(password, label="密码"):
    errors = []
    if len(password) < PASSWORD_MIN_LENGTH:
        errors.append(f"长度至少 {PASSWORD_MIN_LENGTH} 位")
    if not re.search(r"[A-Z]", password):
        errors.append("需要包含大写字母")
    if not re.search(r"[a-z]", password):
        errors.append("需要包含小写字母")
    if not re.search(r"\d", password):
        errors.append("需要包含数字")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>_+\-=\[\]\\;'/`~]", password):
        errors.append("需要包含至少一个特殊字符")
    if errors:
        logger.error("%s 强度不足：%s", label, "；".join(errors))
        print(f"\n❌ {label} 强度不足：{'；'.join(errors)}")
        print(f"   请使用密码管理器生成 {PASSWORD_MIN_LENGTH} 位以上、含大小写+数字+特殊字符的强密码。\n")
        sys.exit(1)


def _get_env_or_fail(key, prompt_name):
    val = os.environ.get(key, "").strip()
    if not val:
        print(f"\n❌ 环境变量 {key} 未设置！请设置 {prompt_name} 的密码。\n")
        sys.exit(1)
    lower = val.lower()
    for p in PLACEHOLDER_PATTERNS:
        if p in lower:
            print(f"\n❌ {key} 包含占位符/弱密码「{p}」，被拒绝。\n")
            sys.exit(1)
    return val


# ---------------------------------------------------------------------------
# Redis 连接 & 账号锁定
# ---------------------------------------------------------------------------
def init_redis(url):
    global _redis
    import redis as r
    _redis = r.from_url(url, socket_connect_timeout=2)
    try:
        _redis.ping()
        logger.info("Redis 连接正常")
    except Exception as e:
        logger.warning("Redis 连接失败，账号锁定功能不可用: %s", e)


def record_login_failure(username):
    key = f"login_fail:{username}"
    try:
        attempts = _redis.incr(key)
        if attempts == 1:
            _redis.expire(key, LOCKOUT_DURATION)
        return attempts
    except Exception:
        return 0


def is_account_locked(username):
    try:
        val = _redis.get(f"login_fail:{username}")
        return val is not None and int(val) >= MAX_LOGIN_ATTEMPTS
    except Exception:
        return False


def get_lockout_ttl(username):
    try:
        return max(_redis.ttl(f"login_fail:{username}"), 0)
    except Exception:
        return 0


def clear_login_failures(username):
    try:
        _redis.delete(f"login_fail:{username}")
    except Exception:
        pass


def redis_healthy():
    try:
        return _redis is not None and _redis.ping()
    except Exception:
        return False


# ---------------------------------------------------------------------------
# 防用户枚举
# ---------------------------------------------------------------------------
def anti_enumeration_delay():
    time.sleep(random.uniform(0.5, 1.5))


# ---------------------------------------------------------------------------
# 安全响应头中间件
# ---------------------------------------------------------------------------
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'"
    )
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response
