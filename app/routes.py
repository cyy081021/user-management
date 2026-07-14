"""
路由模块 — 所有 HTTP 路由定义
"""
import os
import re
import uuid
import logging
from functools import wraps
from decimal import Decimal, InvalidOperation
from flask import Blueprint, render_template, request, redirect, session, url_for, abort, jsonify, g

from app.auth import perform_login
from app.users import get_user_by_id, get_user_role
from app.security import redis_healthy, _check_password_strength
from app.database import get_db
from app.upload_handler import validate_upload
from werkzeug.security import generate_password_hash

main_bp = Blueprint("main", __name__, template_folder="../templates")
logger = logging.getLogger(__name__)

_USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")
_PHONE_RE = re.compile(r"^\+?[0-9]{7,15}$")


# =============================================================
# 装饰器（每次请求从 DB 验证用户存在性）
# =============================================================
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        uid = session.get("user_id")
        if not uid:
            return redirect("/login")
        user = get_user_by_id(uid)
        if not user:
            session.clear()
            return redirect("/login")
        g.current_user = user
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        uid = session.get("user_id")
        if not uid:
            return redirect("/login")
        user = get_user_by_id(uid)
        if not user:
            session.clear()
            return redirect("/login")
        if user.get("role") != "admin":
            abort(403)
        g.current_user = user
        return f(*args, **kwargs)
    return wrapper


def _user_context():
    if "user_id" not in session:
        return None
    uid = session["user_id"]
    return get_user_by_id(uid)


# =============================================================
# 注册字段校验
# =============================================================
def _validate_registration(username, email, phone):
    """返回 (是否通过, 错误提示)"""
    if not username or not username.strip():
        return False, "用户名不能为空"
    username = username.strip()
    if not _USERNAME_RE.match(username):
        return False, "用户名格式不正确（3-32位字母、数字或下划线）"

    if email:
        email = email.strip()
        if len(email) > 254:
            return False, "邮箱格式不正确"
        if "@" not in email or "." not in email.split("@")[-1]:
            return False, "邮箱格式不正确"

    if phone and phone.strip():
        phone = phone.strip()
        if not _PHONE_RE.match(phone):
            return False, "手机号格式不正确（7-15位数字，可选+号前缀）"

    return True, ""


# =============================================================
# 首页
# =============================================================
@main_bp.route("/")
def index():
    user = _user_context()
    keyword = request.args.get("keyword", "").strip()
    search_results = None
    if keyword and user:
        conn = get_db()
        try:
            like = f"%{keyword}%"
            role = user.get("role", "user")
            if role == "admin":
                rows = conn.execute(
                    "SELECT id, username, email, phone, role FROM users WHERE username LIKE ? OR email LIKE ?",
                    (like, like),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT id, username FROM users WHERE username LIKE ?",
                    (like,),
                ).fetchall()
            search_results = [dict(r) for r in rows]
        finally:
            conn.close()

    return render_template("index.html", user=user, keyword=keyword, search_results=search_results)


@main_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        ok, result = perform_login(username, password)
        if ok:
            session.clear()
            session.permanent = True
            session["user_id"] = result["id"]
            session["username"] = result["username"]
            return redirect("/")
        return render_template("login.html", error=result)
    return render_template("login.html")


@main_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()

        # 密码强度
        try:
            _check_password_strength(password, "注册密码")
        except SystemExit:
            return render_template("register.html", error="密码强度不足（≥12位，含大小写+数字+特殊字符）")

        # 字段格式校验
        ok, msg = _validate_registration(username, email, phone)
        if not ok:
            return render_template("register.html", error=msg)

        conn = get_db()
        try:
            hashed = generate_password_hash(password)
            conn.execute(
                "INSERT INTO users (username, password, email, phone, role, password_migrated) VALUES (?, ?, ?, ?, 'user', 1)",
                (username, hashed, email, phone),
            )
            conn.commit()
            logger.info("注册成功: user=%s", username)
            return render_template("login.html", message="注册成功，请登录")
        except Exception as e:
            conn.rollback()
            logger.error("注册失败: user=%s error=%s", username, e)
            return render_template("register.html", error="注册失败，用户名可能已存在")
        finally:
            conn.close()

    return render_template("register.html")


@main_bp.route("/search")
@login_required
def search():
    keyword = request.args.get("keyword", "").strip()
    if not keyword:
        return redirect("/")

    user = g.current_user
    conn = get_db()
    try:
        like = f"%{keyword}%"
        if user.get("role") == "admin":
            rows = conn.execute(
                "SELECT id, username, email, phone, role FROM users WHERE username LIKE ? OR email LIKE ?",
                (like, like),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, username FROM users WHERE username LIKE ?",
                (like,),
            ).fetchall()
        results = [dict(r) for r in rows]
    finally:
        conn.close()

    return render_template("index.html", user=user, keyword=keyword, search_results=results)


@main_bp.route("/profile")
@login_required
def profile():
    uid = session["user_id"]
    target_id = request.args.get("user_id", "").strip()

    if target_id and target_id.isdigit():
        if g.current_user.get("role") != "admin":
            abort(403)
        uid = int(target_id)

    user = get_user_by_id(uid)
    if not user:
        abort(404)

    balance_yuan = user["balance_cents"] / 100.0 if user.get("balance_cents") else 0.0

    pending_orders = None
    if g.current_user.get("role") == "admin":
        conn = get_db()
        try:
            rows = conn.execute(
                "SELECT o.id, o.user_id, o.amount_cents, u.username FROM recharge_orders o "
                "JOIN users u ON o.user_id = u.id WHERE o.status = 'pending' ORDER BY o.created_at"
            ).fetchall()
            pending_orders = [dict(r) for r in rows]
        finally:
            conn.close()

    return render_template("profile.html", user=user, balance_yuan=balance_yuan, pending_orders=pending_orders)


@main_bp.route("/recharge", methods=["POST"])
@login_required
def recharge():
    uid = session["user_id"]
    user = g.current_user
    by = user["balance_cents"] / 100.0 if user else 0.0

    amount_str = request.form.get("amount", "").strip()
    try:
        amount_dec = Decimal(amount_str)
    except InvalidOperation:
        return render_template("profile.html", user=user, balance_yuan=by, error="无效金额")

    if not amount_dec.is_finite():
        return render_template("profile.html", user=user, balance_yuan=by, error="金额必须为有限数字")
    if amount_dec <= 0:
        return render_template("profile.html", user=user, balance_yuan=by, error="金额必须大于0")
    if amount_dec > Decimal("10000.00"):
        return render_template("profile.html", user=user, balance_yuan=by, error="单次充值不超过10000.00元")
    if amount_dec.as_tuple().exponent < -2:
        return render_template("profile.html", user=user, balance_yuan=by, error="金额最多两位小数")

    amount_cents = int(amount_dec * 100)

    conn = get_db()
    try:
        tx_id = uuid.uuid4().hex
        conn.execute(
            "INSERT INTO recharge_orders (transaction_id, user_id, amount_cents, status) VALUES (?, ?, ?, 'pending')",
            (tx_id, uid, amount_cents),
        )
        conn.commit()
        logger.info("充值订单创建: tx=%s user=%d amount=%s", tx_id, uid, amount_str)
    except Exception as e:
        conn.rollback()
        logger.error("充值订单创建失败: %s", e)
        return render_template("profile.html", user=user, balance_yuan=by, error="创建订单失败")
    finally:
        conn.close()

    return render_template("profile.html", user=user, balance_yuan=by,
                           message=f"充值订单已创建（{amount_str}元），等待管理员审批")


@main_bp.route("/admin/approve_recharge", methods=["POST"])
@admin_required
def approve_recharge():
    order_id = request.form.get("order_id", "").strip()
    if not order_id or not order_id.isdigit():
        abort(400)

    conn = get_db()
    try:
        conn.execute("BEGIN EXCLUSIVE")
        order = conn.execute(
            "SELECT id, user_id, amount_cents, status FROM recharge_orders WHERE id = ?",
            (int(order_id),),
        ).fetchone()

        if not order:
            conn.rollback()
            return jsonify({"error": "订单不存在"}), 404

        if order["status"] != "pending":
            conn.rollback()
            return jsonify({"error": "订单已处理"}), 409

        cur = conn.execute(
            "UPDATE recharge_orders SET status = 'approved', approved_by = ?, updated_at = datetime('now') "
            "WHERE id = ? AND status = 'pending'",
            (session["user_id"], order["id"]),
        )
        if cur.rowcount != 1:
            conn.rollback()
            return jsonify({"error": "订单已被其他管理员处理"}), 409

        conn.execute(
            "UPDATE users SET balance_cents = balance_cents + ? WHERE id = ?",
            (order["amount_cents"], order["user_id"]),
        )
        conn.commit()
        logger.info("充值审批通过: order=%d user=%d amount_cents=%d", order["id"], order["user_id"], order["amount_cents"])
    except Exception:
        conn.rollback()
        logger.exception("审批失败")
        return jsonify({"error": "审批失败"}), 500
    finally:
        conn.close()

    return redirect("/profile")


@main_bp.route("/change-password", methods=["POST"])
def change_password():
    if "user_id" not in session:
        return redirect("/login")

    username = request.form.get("username", "").strip()
    new_password = request.form.get("new_password", "")

    if not username or not new_password:
        return "用户名和新密码不能为空", 400

    conn = get_db()
    try:
        hashed = generate_password_hash(new_password)
        conn.execute(
            "UPDATE users SET password = ?, password_migrated = 1 WHERE username = ?",
            (hashed, username),
        )
        conn.commit()
        logger.info("密码已修改: user=%s", username)
    except Exception as e:
        conn.rollback()
        logger.error("修改密码失败: %s", e)
        return "修改失败", 500
    finally:
        conn.close()

    return redirect("/profile")


@main_bp.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect("/login")


@main_bp.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    if request.method == "POST":
        file = request.files.get("file")
        ok, message, result = validate_upload(file)
        if ok:
            return render_template("upload.html", success=True, file_url=result["url"], filename=result["display_name"])
        return render_template("upload.html", error=message)
    return render_template("upload.html")


@main_bp.route("/uploads/<filename>")
def uploaded_file(filename):
    from flask import send_from_directory
    from app.upload_handler import UPLOAD_DIR
    safe_name = os.path.basename(filename)
    if not (UPLOAD_DIR / safe_name).exists():
        abort(404)
    ext = os.path.splitext(safe_name)[1].lower()
    m = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif", ".webp": "image/webp"}
    response = send_from_directory(str(UPLOAD_DIR), safe_name)
    response.headers["Content-Type"] = m.get(ext, "application/octet-stream")
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Disposition"] = "inline"
    response.headers["Cache-Control"] = "no-store"
    return response


@main_bp.route("/page")
def page():
    """白名单映射：名称 → 固定模板，不读取文件"""
    PAGE_TEMPLATES = {"help": "pages/help.html"}
    name = request.args.get("name", "").strip()
    template = PAGE_TEMPLATES.get(name)
    if not template:
        return "页面不存在", 404
    return render_template(template, user=_user_context())


@main_bp.route("/health")
def health():
    return {"status": "ok", "service": "user-management", "redis": redis_healthy()}
