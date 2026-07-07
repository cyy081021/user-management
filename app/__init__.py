"""
用户信息管理平台 — 应用工厂

使用方式：
  export ADMIN_PASSWORD="..." ALICE_PASSWORD="..." SECRET_KEY="..."
  gunicorn wsgi:app
"""
import os
import sys
import logging
from datetime import timedelta

from flask import Flask
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from app.security import (
    _get_env_or_fail,
    _check_password_strength,
    init_redis,
    add_security_headers,
)
from app.users import USERS, _init_users
from app.routes import main_bp

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 日志配置
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()],
)

# ---------------------------------------------------------------------------
# 启动前校验
# ---------------------------------------------------------------------------
_ADMIN_PW = _get_env_or_fail("ADMIN_PASSWORD", "管理员(admin)")
_ALICE_PW = _get_env_or_fail("ALICE_PASSWORD", "普通用户(alice)")
_check_password_strength(_ADMIN_PW, "ADMIN_PASSWORD")
_check_password_strength(_ALICE_PW, "ALICE_PASSWORD")
_HTTPS = os.environ.get("FLASK_HTTPS", "0") == "1"
_SECRET_KEY = os.environ.get("SECRET_KEY", "").strip() or os.urandom(32).hex()

if not os.environ.get("SECRET_KEY"):
    logger.warning("SECRET_KEY 未设置，已自动生成（重启后会话失效）")


# ---------------------------------------------------------------------------
# 应用工厂
# ---------------------------------------------------------------------------
def create_app():
    app = Flask(__name__, template_folder="../templates", static_folder="../static")
    app.secret_key = _SECRET_KEY

    # Session 安全
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = _HTTPS
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=2)
    app.config["WTF_CSRF_TIME_LIMIT"] = 3600

    # CSRF
    CSRFProtect(app)

    # 限流器（Redis 共享）
    redis_url = os.environ.get("REDIS_URL", "redis://127.0.0.1:6379/0")
    Limiter(
        get_remote_address,
        app=app,
        default_limits=["200 per day", "50 per hour"],
        storage_uri=redis_url,
        storage_options={"socket_connect_timeout": 2},
    )

    # 初始化 Redis 连接 & 用户数据
    init_redis(redis_url)
    _init_users(_ADMIN_PW, _ALICE_PW)

    # 注册蓝图
    app.register_blueprint(main_bp)

    # 安全响应头
    app.after_request(add_security_headers)

    return app
