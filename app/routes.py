"""
路由模块 — 所有 HTTP 路由定义
"""
from flask import Blueprint, render_template, request, redirect, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from app.auth import perform_login
from app.users import get_safe_user_info
from app.security import redis_healthy

main_bp = Blueprint("main", __name__, template_folder="../templates")


@main_bp.route("/")
def index():
    username = session.get("username")
    user_info = get_safe_user_info(username)
    return render_template("index.html", username=username, user=user_info)


@main_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        ok, result = perform_login(username, password)
        if ok:
            session.permanent = True
            session["username"] = username
            return render_template("index.html", username=username, user=result)
        return render_template("login.html", error=result)
    return render_template("login.html")


@main_bp.route("/logout")
def logout():
    username = session.get("username", "unknown")
    session.clear()
    from app import logger
    logger.info("用户 '%s' 已退出", username)
    return redirect("/")


@main_bp.route("/health")
def health():
    return {
        "status": "ok",
        "service": "user-management",
        "redis": redis_healthy(),
    }
