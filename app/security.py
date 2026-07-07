"""
安全工具模块 — 密码校验、环境变量检查、Redis 连接、安全响应头
"""
import os
import sys
import re
import time
import random
import hashlib
import logging

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------
PASSWORD_MIN_LENGTH = 12
PLACEHOLDER_PATTERNS = [
    "在此处填写", "your_", "placeholder", "changeme",
    "change_me", "passw0rd", "123456", "qwerty",
]

# 渐进延迟阶梯（秒）：第 1 次失败等 1s，第 5 次等 8s...
DELAY_STEPS = [1, 1, 2, 4, 8, 16, 30, 60]

# 超过此上限的"连续失败"视为异常，返回通用错误但不通知"锁定"
ABUSE_THRESHOLD = 20

_redis = None  # lazy init


# ---------------------------------------------------------------------------
# SECRET_KEY 强度校验
# ---------------------------------------------------------------------------
def validate_secret_key(key):
    """校验 SECRET_KEY 强度，不符合则退出"""
    if not key:
        print("\n❌ 生产环境必须设置 SECRET_KEY 环境变量。\n"
              "   建议: python3 -c 'import secrets; print(secrets.token_hex(32))'\n")
        sys.exit(1)
    if len(key) < 32:
        print(f"\n❌ SECRET_KEY 长度不足（当前 {len(key)}，需要 ≥32 字符）\n")
        sys.exit(1)
    # 检查熵：是否全是重复字符或简单模式
    unique = len(set(key))
    if unique < 10:
        print(f"\n❌ SECRET_KEY 熵值过低（仅 {unique} 种不同字符），请使用高熵随机密钥\n")
        sys.exit(1)


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
# Redis 连接 & 渐进延迟
# ---------------------------------------------------------------------------
def init_redis(url):
    global _redis
    import redis as r
    _redis = r.from_url(url, socket_connect_timeout=2)
    try:
        _redis.ping()
        logger.info("Redis 连接正常")
    except Exception as e:
        logger.warning("Redis 连接失败，渐进延迟降级为固定 2s: %s", e)


def _ensure_redis():
    """返回 _redis 或 None（允许降级）"""
    try:
        if _redis is not None and _redis.ping():
            return _redis
    except Exception:
        pass
    return None


def _fmt_key(username, ip=""):
    """以用户名+IP 构建键，降低误锁风险"""
    tag = hashlib.md5(ip.encode()).hexdigest()[:8] if ip else "global"
    return f"login_fail:{username}:{tag}"


def record_login_failure(username, ip=""):
    """
    记录失败，返回本次应等待的秒数（渐进延迟）
    不再硬锁定——极端高频会持续增长延迟，但不暴露"账号已锁定"信息。
    """
    key = _fmt_key(username, ip)
    r = _ensure_redis()
    if r is None:
        return 2.0  # 降级：固定 2 秒

    try:
        attempts = r.incr(key)
        if attempts == 1:
            r.expire(key, 3600)  # 1 小时后自动重置
        step_idx = min(attempts - 1, len(DELAY_STEPS) - 1)
        return float(DELAY_STEPS[step_idx])
    except Exception:
        return 2.0


def get_login_delay(username, ip=""):
    """
    读取当前已累积的延迟（不递增计数），用于登录前的延迟等待。
    返回等待秒数。
    """
    key = _fmt_key(username, ip)
    r = _ensure_redis()
    if r is None:
        return 2.0
    try:
        val = r.get(key)
        if val is None:
            return 0
        attempts = int(val)
        step_idx = min(attempts - 1, len(DELAY_STEPS) - 1)
        return float(DELAY_STEPS[step_idx])
    except Exception:
        return 2.0


def clear_login_failures(username, ip=""):
    """登录成功后清除"""
    r = _ensure_redis()
    if r is None:
        return
    try:
        r.delete(_fmt_key(username, ip))
    except Exception:
        pass


def redis_healthy():
    try:
        return _redis is not None and _redis.ping()
    except Exception:
        return False


# ---------------------------------------------------------------------------
# 防用户枚举（基线延迟 + 渐进延迟）
# ---------------------------------------------------------------------------
def anti_enumeration_delay(extra=0):
    time.sleep(random.uniform(0.5, 1.5) + extra)


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
