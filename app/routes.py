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
from app.upload_handler import validate_upload

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
        ok, message, result = validate_upload(file)
        if ok:
            return render_template("upload.html", success=True, file_url=result["url"], filename=result["display_name"])
        return render_template("upload.html", error=message)

    return render_template("upload.html")


@main_bp.route("/uploads/<filename>")
def uploaded_file(filename):
    """受控的文件下载/预览接口"""
    from flask import send_from_directory, abort
    from app.upload_handler import UPLOAD_DIR

    safe_name = os.path.basename(filename)
    file_path = UPLOAD_DIR / safe_name
    if not file_path.exists():
        abort(404)

    # 根据扩展名设置 Content-Type
    ext = os.path.splitext(safe_name)[1].lower()
    mime_map = {
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".gif": "image/gif",
        ".webp": "image/webp",
    }
    mime = mime_map.get(ext, "application/octet-stream")

    response = send_from_directory(str(UPLOAD_DIR), safe_name)
    response.headers["Content-Type"] = mime
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Disposition"] = "inline"
    response.headers["Cache-Control"] = "no-store"
    return response


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
