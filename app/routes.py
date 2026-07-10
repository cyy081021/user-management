"""
路由模块 — 所有 HTTP 路由定义
"""
import os
import uuid
import logging
from functools import wraps
from decimal import Decimal, InvalidOperation
from flask import Blueprint, render_template, request, redirect, session, url_for, abort, jsonify

from app.auth import perform_login
from app.users import get_user_by_id, get_user_role
from app.security import redis_healthy, _check_password_strength
from app.database import get_db
from app.upload_handler import validate_upload
from werkzeug.security import generate_password_hash

main_bp = Blueprint("main", __name__, template_folder="../templates")
logger = logging.getLogger(__name__)


# =============================================================
# 装饰器
# =============================================================
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect("/login")
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    """每次请求从 DB 读取当前角色，不信任 session 缓存"""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect("/login")
        role = get_user_role(session["user_id"])
        if role != "admin":
            abort(403)
        return f(*args, **kwargs)
    return wrapper


def _user_context():
    uid = session.get("user_id")
    if uid:
        return get_user_by_id(uid)
    return None


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
            role = get_user_role(user["id"])
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


# =============================================================
# 登录
# =============================================================
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


# =============================================================
# 注册
# =============================================================
@main_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()

        try:
            _check_password_strength(password, "注册密码")
        except SystemExit:
            return render_template("register.html", error="密码强度不足（≥12位，含大小写+数字+特殊字符）")

        conn = get_db()
        try:
            hashed = generate_password_hash(password)
            conn.execute(
                "INSERT INTO users (username, password, email, phone, role, password_migrated) VALUES (?, ?, ?, ?, 'user', 1)",
                (username, hashed, email, phone),
            )
            conn.commit()
            logger.info("注册成功: %s", username)
            return render_template("login.html", message="注册成功，请登录")
        except Exception as e:
            conn.rollback()
            logger.error("注册失败: user=%s error=%s", username, e)
            return render_template("register.html", error="注册失败，用户名可能已存在")
        finally:
            conn.close()

    return render_template("register.html")


# =============================================================
# 搜索（需登录，按角色限制字段）
# =============================================================
@main_bp.route("/search")
@login_required
def search():
    keyword = request.args.get("keyword", "").strip()
    if not keyword:
        return redirect("/")

    uid = session["user_id"]
    role = get_user_role(uid)
    conn = get_db()
    try:
        like = f"%{keyword}%"
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
        results = [dict(r) for r in rows]
    finally:
        conn.close()

    return render_template("index.html", user=_user_context(), keyword=keyword, search_results=results)


# =============================================================
# 个人中心
# =============================================================
@main_bp.route("/profile")
@login_required
def profile():
    uid = session["user_id"]
    target_id = request.args.get("user_id", "").strip()

    if target_id and target_id.isdigit():
        role = get_user_role(uid)
        if role != "admin":
            abort(403)
        uid = int(target_id)

    user = get_user_by_id(uid)
    if not user:
        abort(404)

    balance_yuan = user["balance_cents"] / 100.0 if user.get("balance_cents") else 0.0

    # 管理员可见待审批订单（实时从 DB 读角色）
    pending_orders = None
    if get_user_role(session["user_id"]) == "admin":
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


# =============================================================
# 充值申请
# =============================================================
@main_bp.route("/recharge", methods=["POST"])
@login_required
def recharge():
    uid = session["user_id"]
    user = get_user_by_id(uid)
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
        logger.info("充值订单创建: tx=%s user=%s amount=%s", tx_id, uid, amount_str)
    except Exception as e:
        conn.rollback()
        logger.error("充值订单创建失败: %s", e)
        return render_template("profile.html", user=user, balance_yuan=by, error="创建订单失败")
    finally:
        conn.close()

    return render_template("profile.html", user=user, balance_yuan=by,
                           message=f"充值订单已创建（{amount_str}元），等待管理员审批")


# =============================================================
# 管理员审批充值（原子事务：BEGIN IMMEDIATE + 条件更新）
# =============================================================
@main_bp.route("/admin/approve_recharge", methods=["POST"])
@admin_required
def approve_recharge():
    order_id = request.form.get("order_id", "").strip()
    if not order_id or not order_id.isdigit():
        abort(400)

    conn = get_db()
    try:
        # BEGIN IMMEDIATE 获取 XL 写锁，防止并发竞态
        conn.execute("BEGIN IMMEDIATE")

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

        # 原子抢占：条件更新，rowcount 为 1 表示我们拿到了
        cursor = conn.execute(
            "UPDATE recharge_orders SET status = 'approved', approved_by = ?, updated_at = datetime('now') "
            "WHERE id = ? AND status = 'pending'",
            (session["user_id"], order["id"]),
        )
        if cursor.rowcount != 1:
            conn.rollback()
            return jsonify({"error": "订单已被其他管理员处理"}), 409

        # 增加余额（同一事务内）
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


# =============================================================
# 退出
# =============================================================
@main_bp.route("/logout", methods=["POST"])
def logout():
    username = session.get("username", "unknown")
    session.clear()
    logger.info("用户 '%s' 已退出", username)
    return redirect("/login")


# =============================================================
# 上传
# =============================================================
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
    file_path = UPLOAD_DIR / safe_name
    if not file_path.exists():
        abort(404)
    ext = os.path.splitext(safe_name)[1].lower()
    mime_map = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif", ".webp": "image/webp"}
    mime = mime_map.get(ext, "application/octet-stream")
    response = send_from_directory(str(UPLOAD_DIR), safe_name)
    response.headers["Content-Type"] = mime
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Disposition"] = "inline"
    response.headers["Cache-Control"] = "no-store"
    return response


@main_bp.route("/health")
def health():
    return {"status": "ok", "service": "user-management", "redis": redis_healthy()}
