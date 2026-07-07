"""
用户信息管理平台 - 主应用
"""
import os
import re
import sys
import time
import random
import logging
from datetime import timedelta

from flask import Flask, render_template, request, redirect, session
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash

# ---------------------------------------------------------------------------
# 日志配置
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 密码强度校验
# ---------------------------------------------------------------------------
_PASSWORD_MIN_LENGTH = 12


def _check_password_strength(password, label="密码"):
    """检查密码强度，通过返回 True，否则抛出 SystemExit"""
    errors = []
    if len(password) < _PASSWORD_MIN_LENGTH:
        errors.append(f"长度至少 {_PASSWORD_MIN_LENGTH} 位")
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
        print(f"   请使用密码管理器生成 {_PASSWORD_MIN_LENGTH} 位以上、含大小写+数字+特殊字符的强密码。\n")
        sys.exit(1)
    return True


# ---------------------------------------------------------------------------
# 从环境变量读取配置（拒绝占位符）
# ---------------------------------------------------------------------------
_PLACEHOLDER_PATTERNS = [
    "在此处填写",
    "your_",
    "your-pass",
    "placeholder",
    "changeme",
    "change_me",
    "password",
    "passw0rd",
    "123456",
    "qwerty",
]


def _get_env_or_fail(key, prompt_name):
    val = os.environ.get(key, "").strip()
    if not val:
        print(f"\n❌ 环境变量 {key} 未设置！请设置 {prompt_name} 的密码。")
        print(f"   推荐: 用密码管理器生成一个 {_PASSWORD_MIN_LENGTH} 位以上的强密码。\n")
        sys.exit(1)

    lower = val.lower()
    for p in _PLACEHOLDER_PATTERNS:
        if p in lower:
            print(f"\n❌ {key} 包含占位符/弱密码「{p}」，被拒绝。")
            print(f"   请设置一个真正的强密码。\n")
            sys.exit(1)
    return val


# 优先从环境变量读取稳定密钥，否则随机生成（多 worker 部署建议固定）
SECRET_KEY = os.environ.get("SECRET_KEY", "").strip()
if not SECRET_KEY:
    SECRET_KEY = os.urandom(32).hex()
    logger.warning("SECRET_KEY 未设置，已自动生成随机密钥（重启后会话将失效）")

ADMIN_PASSWORD = _get_env_or_fail("ADMIN_PASSWORD", "管理员(admin)")
ALICE_PASSWORD = _get_env_or_fail("ALICE_PASSWORD", "普通用户(alice)")

# 启动时强制校验密码强度
_check_password_strength(ADMIN_PASSWORD, "ADMIN_PASSWORD")
_check_password_strength(ALICE_PASSWORD, "ALICE_PASSWORD")

# 是否启用 HTTPS
_HTTPS_ENABLED = os.environ.get("FLASK_HTTPS", "0") == "1"

# ---------------------------------------------------------------------------
# Flask 应用初始化
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = SECRET_KEY

# Session 安全配置
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = _HTTPS_ENABLED
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=2)

# CSRF
app.config["WTF_CSRF_TIME_LIMIT"] = 3600
csrf = CSRFProtect(app)

# ---------------------------------------------------------------------------
# 限流器（Redis 共享存储，多 worker 实例计数一致）
# ---------------------------------------------------------------------------
_REDIS_URL = os.environ.get("REDIS_URL", "redis://127.0.0.1:6379/0")

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri=_REDIS_URL,
    storage_options={"socket_connect_timeout": 2},
)

# ---------------------------------------------------------------------------
# 按用户名维度失败计数 & 临时锁定
# ---------------------------------------------------------------------------
import redis as _redis_client

_redis = _redis_client.from_url(_REDIS_URL, socket_connect_timeout=2)

_MAX_LOGIN_ATTEMPTS = 5
_LOCKOUT_DURATION = 900  # 15 分钟


def _record_login_failure(username):
    """记录登录失败，达到阈值则锁定"""
    key = f"login_fail:{username}"
    attempts = _redis.incr(key)
    if attempts == 1:
        _redis.expire(key, _LOCKOUT_DURATION)
    return attempts


def _is_account_locked(username):
    """检查账号是否已被锁定"""
    return _redis.get(f"login_fail:{username}") is not None and int(
        _redis.get(f"login_fail:{username}")
    ) >= _MAX_LOGIN_ATTEMPTS


def _clear_login_failures(username):
    """登录成功时清除失败记录"""
    _redis.delete(f"login_fail:{username}")


# ---------------------------------------------------------------------------
# 用户数据库（密码以 PBKDF2 哈希存储，源码中无明文）
# ---------------------------------------------------------------------------
USERS = {
    "admin": {
        "username": "admin",
        "password": generate_password_hash(ADMIN_PASSWORD),
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999,
    },
    "alice": {
        "username": "alice",
        "password": generate_password_hash(ALICE_PASSWORD),
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100,
    },
}


def get_safe_user_info(username):
    """返回不包含密码字段的用户信息"""
    if username in USERS:
        info = USERS[username].copy()
        info.pop("password", None)
        return info
    return None


# ---------------------------------------------------------------------------
# 防用户枚举：登录失败时随机延迟
# ---------------------------------------------------------------------------
def _anti_enumeration_delay():
    time.sleep(random.uniform(0.5, 1.5))


# ---------------------------------------------------------------------------
# 路由
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    username = session.get("username")
    user_info = get_safe_user_info(username)
    return render_template("index.html", username=username, user=user_info)


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        _anti_enumeration_delay()

        # 检查账号是否被锁定
        if _is_account_locked(username):
            remaining = _redis.ttl(f"login_fail:{username}")
            logger.warning("账号 '%s' 已锁定（剩余 %ds）", username, remaining)
            return render_template(
                "login.html",
                error=f"账号已被临时锁定，请 {max(remaining, 0)} 秒后再试",
            )

        if username in USERS and check_password_hash(USERS[username]["password"], password):
            session.permanent = True
            session["username"] = username
            _clear_login_failures(username)
            logger.info("用户 '%s' 登录成功", username)
            return render_template("index.html", username=username, user=get_safe_user_info(username))

        # 登录失败 → 记录失败次数
        attempts = _record_login_failure(username)
        logger.info("用户 '%s' 登录失败（第 %d 次）", username, attempts)
        return render_template("login.html", error="用户名或密码错误")

    return render_template("login.html")


@app.route("/logout")
def logout():
    username = session.get("username", "unknown")
    session.clear()
    logger.info("用户 '%s' 已退出", username)
    return redirect("/")


@app.route("/health")
def health():
    redis_ok = False
    try:
        redis_ok = _redis.ping()
    except Exception:
        pass
    return {"status": "ok", "service": "user-management", "redis": redis_ok}


# ---------------------------------------------------------------------------
# 安全响应头
# ---------------------------------------------------------------------------
@app.after_request
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


# ---------------------------------------------------------------------------
# 启动入口
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    use_https = _HTTPS_ENABLED
    ssl_context = None

    if use_https:
        cert = "/root/ssl/cert.pem"
        key = "/root/ssl/key.pem"
        if os.path.exists(cert) and os.path.exists(key):
            ssl_context = (cert, key)
            logger.info("HTTPS 已启用")
        else:
            logger.warning("SSL 证书不存在，回退 HTTP")
            use_https = False

    if not use_https:
        logger.info("HTTP 模式（生产环境建议启用 HTTPS 或使用 Nginx 反代）")

    logger.info("服务启动于 %s://0.0.0.0:5000", "https" if use_https else "http")
    app.run(debug=False, host="0.0.0.0", port=5000, ssl_context=ssl_context)
