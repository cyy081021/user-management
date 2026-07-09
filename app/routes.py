"""
路由模块 — 所有 HTTP 路由定义（使用参数化查询，修复 SQL 注入）
"""
import os
import logging
from flask import Blueprint, render_template, request, redirect, session, url_for

from app.auth import perform_login
from app.users import get_safe_user_info
from app.security import redis_healthy
from app.database import get_db

main_bp = Blueprint("main", __name__, template_folder="../templates")
logger = logging.getLogger(__name__)


@main_bp.route("/")
def index():
    username = session.get("username")
    user_info = get_safe_user_info(username)

    # 搜索功能（使用参数化查询）
    keyword = request.args.get("keyword", "").strip()
    search_results = None
    if keyword:
        conn = get_db()
        cursor = conn.cursor()
        like_pattern = f"%{keyword}%"
        cursor.execute(
            "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?",
            (like_pattern, like_pattern),
        )
        search_results = [dict(row) for row in cursor.fetchall()]
        conn.close()

    return render_template(
        "index.html",
        username=username,
        user=user_info,
        keyword=keyword,
        search_results=search_results,
    )


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


@main_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()

        conn = get_db()
        cursor = conn.cursor()
        # 使用参数化查询插入用户
        try:
            cursor.execute(
                "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
                (username, password, email, phone),
            )
            conn.commit()
            logger.info("[注册] 用户 '%s' 注册成功", username)
            conn.close()
            return render_template("login.html", message="注册成功，请登录")
        except Exception as e:
            logger.error("[注册错误] %s", e)
            conn.close()
            return render_template("register.html", error=f"注册失败：{e}")

    return render_template("register.html")


@main_bp.route("/search")
def search():
    keyword = request.args.get("keyword", "").strip()
    if not keyword:
        return redirect("/")

    conn = get_db()
    cursor = conn.cursor()
    like_pattern = f"%{keyword}%"
    cursor.execute(
        "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?",
        (like_pattern, like_pattern),
    )
    results = [dict(row) for row in cursor.fetchall()]
    conn.close()

    username = session.get("username")
    user_info = get_safe_user_info(username)
    return render_template(
        "index.html",
        username=username,
        user=user_info,
        keyword=keyword,
        search_results=results,
    )


@main_bp.route("/upload", methods=["GET", "POST"])
def upload():
    if "username" not in session:
        return redirect("/login")

    if request.method == "POST":
        file = request.files.get("file")
        if not file or file.filename == "":
            return render_template("upload.html", error="请选择文件")

        filename = file.filename
        upload_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static", "uploads")
        os.makedirs(upload_dir, exist_ok=True)
        save_path = os.path.join(upload_dir, filename)
        file.save(save_path)

        file_url = url_for("static", filename=f"uploads/{filename}")
        return render_template("upload.html", success=True, file_url=file_url, filename=filename)

    return render_template("upload.html")


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
