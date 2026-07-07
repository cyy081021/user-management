from flask import Flask, render_template, request, redirect, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from wtforms import Form, StringField, PasswordField, validators
import os
import time
import random
import logging

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
# Flask 应用初始化
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = os.urandom(24).hex()

# Session 安全配置
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# CSRF 保护
app.config["WTF_CSRF_TIME_LIMIT"] = 3600  # CSRF token 有效期 1 小时
csrf = CSRFProtect(app)

# 速率限制
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

# ---------------------------------------------------------------------------
# 从环境变量读取密码（绝不硬编码！）
# ---------------------------------------------------------------------------
def _get_env_password(key, prompt_name):
    """从环境变量获取密码，缺失时抛错"""
    password = os.environ.get(key)
    if not password:
        raise RuntimeError(
            f"环境变量 {key} 未设置！请先设置 {prompt_name} 的密码，例如:\n"
            f"  export {key}=your_password\n"
            f"  或通过 .env 文件加载"
        )
    return password


_admin_password = _get_env_password("ADMIN_PASSWORD", "管理员(admin)")
_alice_password = _get_env_password("ALICE_PASSWORD", "普通用户(alice)")


# ---------------------------------------------------------------------------
# 用户数据库（密码以 PBKDF2 哈希存储，源码中无明文密码）
# ---------------------------------------------------------------------------
USERS = {
    "admin": {
        "username": "admin",
        "password": generate_password_hash(_admin_password),
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999,
    },
    "alice": {
        "username": "alice",
        "password": generate_password_hash(_alice_password),
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100,
    },
}


# ---------------------------------------------------------------------------
# 密码复杂度校验函数
# ---------------------------------------------------------------------------
def check_password_strength(password):
    """检查密码强度，返回 (是否通过, 错误信息)"""
    errors = []
    if len(password) < 8:
        errors.append("密码长度至少 8 位")
    if not any(c.isupper() for c in password):
        errors.append("密码需要包含大写字母")
    if not any(c.islower() for c in password):
        errors.append("密码需要包含小写字母")
    if not any(c.isdigit() for c in password):
        errors.append("密码需要包含数字")
    return (len(errors) == 0, "；".join(errors) if errors else "")


def get_safe_user_info(username):
    """返回不包含密码字段的用户信息"""
    if username in USERS:
        info = USERS[username].copy()
        info.pop("password", None)
        return info
    return None


# ---------------------------------------------------------------------------
# 防用户枚举：登录失败时随机延迟 0.5~1.5 秒
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
@limiter.limit("10 per minute")  # 单 IP 每分钟最多 10 次登录尝试
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # 校验密码复杂度（仅对新密码做提示，不阻止登录）
        is_strong, strength_msg = check_password_strength(password)
        if not is_strong:
            logger.warning("登录尝试使用了弱密码: %s", strength_msg)

        # 防用户枚举：先延迟再验证
        _anti_enumeration_delay()

        # 安全验证密码
        if username in USERS and check_password_hash(USERS[username]["password"], password):
            session["username"] = username
            user_info = get_safe_user_info(username)
            logger.info("用户 '%s' 登录成功", username)
            return render_template("index.html", username=username, user=user_info)

        logger.info("用户 '%s' 登录失败", username)
        return render_template("login.html", error="用户名或密码错误")

    return render_template("login.html")


@app.route("/logout")
def logout():
    username = session.get("username", "unknown")
    session.clear()
    logger.info("用户 '%s' 已退出登录", username)
    return redirect("/")


@app.route("/health")
def health():
    """健康检查端点"""
    return {"status": "ok", "service": "user-management"}

# ---------------------------------------------------------------------------
# 安全响应头中间件
# ---------------------------------------------------------------------------
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


# ---------------------------------------------------------------------------
# 启动入口
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    use_https = os.environ.get("FLASK_HTTPS", "0") == "1"

    ssl_context = None
    if use_https:
        ssl_context = ("/root/ssl/cert.pem", "/root/ssl/key.pem")
        logger.info("HTTPS 已启用")
    else:
        logger.info("HTTP 模式运行（生产环境建议启用 HTTPS）")

    logger.info("服务启动于 http://0.0.0.0:5000")
    app.run(
        debug=debug_mode,
        host="0.0.0.0",
        port=5000,
        ssl_context=ssl_context,
    )
