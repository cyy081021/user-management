"""
用户信息管理平台 — 应用工厂
"""
import os
import logging
from datetime import timedelta

from flask import Flask
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from app.security import (
    _get_env_or_fail,
    _check_password_strength,
    validate_secret_key,
    init_redis,
    add_security_headers,
)
from app.database import init_db
from app.routes import main_bp

logger = logging.getLogger(__name__)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()],
)


def create_app():
    app_env = os.environ.get("APP_ENV", "development").lower()
    is_production = app_env == "production"

    admin_pw = _get_env_or_fail("ADMIN_PASSWORD", "管理员(admin)")
    alice_pw = _get_env_or_fail("ALICE_PASSWORD", "普通用户(alice)")
    _check_password_strength(admin_pw, "ADMIN_PASSWORD")
    _check_password_strength(alice_pw, "ALICE_PASSWORD")

    secret_key = os.environ.get("SECRET_KEY", "").strip()
    if is_production and not secret_key:
        print("\n❌ 生产模式（APP_ENV=production）必须设置 SECRET_KEY。")
        import sys
        sys.exit(1)
    if not secret_key:
        logger.warning("SECRET_KEY 未设置，已自动生成")
        secret_key = os.urandom(32).hex()
    else:
        validate_secret_key(secret_key)

    app = Flask(__name__, template_folder="../templates", static_folder="../static")
    app.secret_key = secret_key

    https_enabled = os.environ.get("FLASK_HTTPS", "0") == "1"

    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = https_enabled or is_production
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=2)
    app.config["WTF_CSRF_TIME_LIMIT"] = 3600
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

    CSRFProtect(app)

    redis_url = os.environ.get("REDIS_URL", "redis://127.0.0.1:6379/0")
    Limiter(
        get_remote_address,
        app=app,
        default_limits=["200 per day", "50 per hour"],
        storage_uri=redis_url,
        storage_options={"socket_connect_timeout": 2},
    )

    init_redis(redis_url)

    # 初始化数据库（传入哈希后的密码）
    init_db(admin_pw=admin_pw, alice_pw=alice_pw)
    admin_pw = alice_pw = None

    app.register_blueprint(main_bp)
    app.after_request(add_security_headers)

    return app
