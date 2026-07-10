"""
路由模块 — 所有 HTTP 路由定义
"""
import os
import logging
from decimal import Decimal, InvalidOperation
from flask import Blueprint, render_template, request, redirect, session, url_for, abort

from app.auth import perform_login
from app.users import get_user_by_id
from app.security import redis_healthy, _check_password_strength
from app.database import get_db
from app.upload_handler import validate_upload
from werkzeug.security import generate_password_hash

main_bp = Blueprint("main", __name__, template_folder="../templates")
logger = logging.getLogger(__name__)


def login_required():
    if "user_id" not in session:
        return redirect("/login")


def _user_context():
    """从 session 获取当前用户信息"""
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
    if keyword:
        conn = get_db()
        try:
            like = f"%{keyword}%"
            rows = conn.execute(
                "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?",
                (like, like),
            ).fetchall()
            search_results = [dict(r) for r in rows]
        finally:
            conn.close()

    return render_template("index.html", user=user, keyword=keyword, search_results=search_results)


# =============================================================
# 登录（统一数据源：SQLite users 表）
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
            session["role"] = result.get("role", "user")
            return redirect("/")
        return render_template("login.html", error=result)
    return render_template("login.html")


# =============================================================
# 注册（写入 SQLite，密码哈希，强度校验）
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
                "INSERT INTO users (username, password, email, phone, role) VALUES (?, ?, ?, ?, 'user')",
                (username, hashed, email, phone),
            )
            conn.commit()
            logger.info("注册成功: %s", username)
            return render_template("login.html", message="注册成功，请登录")
        except Exception as e:
            conn.rollback()
            return render_template("register.html", error=f"注册失败：{e}")
        finally:
            conn.close()

    return render_template("register.html")


# =============================================================
# 搜索（公开，仅返回基本信息）
# =============================================================
@main_bp.route("/search")
def search():
    keyword = request.args.get("keyword", "").strip()
    if not keyword:
        return redirect("/")

    conn = get_db()
    try:
        like = f"%{keyword}%"
        rows = conn.execute(
            "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?",
            (like, like),
        ).fetchall()
        results = [dict(r) for r in rows]
    finally:
        conn.close()

    return render_template("index.html", user=_user_context(), keyword=keyword, search_results=results)


# =============================================================
# 个人中心（仅当前登录用户）
# =============================================================
@main_bp.route("/profile")
def profile():
    if "user_id" not in session:
        return redirect("/login")

    uid = session["user_id"]
    # 管理员可通过 ?user_id=X 查询其他用户
    target_id = request.args.get("user_id", "").strip()
    if target_id and target_id.isdigit():
        if session.get("role") != "admin":
            abort(403)
        uid = int(target_id)

    user = get_user_by_id(uid)
    if not user:
        abort(404)

    # balance_cents → 元
    balance_yuan = user["balance_cents"] / 100.0 if user.get("balance_cents") else 0.0

    # 管理员可见待审批订单
    pending_orders = None
    if session.get("role") == "admin":
        conn2 = get_db()
        try:
            rows = conn2.execute(
                "SELECT o.id, o.user_id, o.amount_cents, u.username FROM recharge_orders o JOIN users u ON o.user_id = u.id WHERE o.status = 'pending' ORDER BY o.created_at"
            ).fetchall()
            pending_orders = [dict(r) for r in rows]
        finally:
            conn2.close()

    return render_template("profile.html", user=user, balance_yuan=balance_yuan, pending_orders=pending_orders)


# =============================================================
# 充值申请（仅创建 pending 订单，不立即入账）
# =============================================================
@main_bp.route("/recharge", methods=["POST"])
def recharge():
    if "user_id" not in session:
        return redirect("/login")

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
        import uuid
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

    return render_template("profile.html", user=user, balance_yuan=by, message=f"充值订单已创建（{amount_str}元），等待管理员审批", pending_orders=None)


# =============================================================
# 管理员审批充值
# =============================================================
@main_bp.route("/admin/approve_recharge", methods=["POST"])
def approve_recharge():
    if session.get("role") != "admin":
        abort(403)

    order_id = request.form.get("order_id", "").strip()
    if not order_id or not order_id.isdigit():
        abort(400)

    conn = get_db()
    try:
        order = conn.execute(
            "SELECT id, user_id, amount_cents, status FROM recharge_orders WHERE id = ?",
            (int(order_id),),
        ).fetchone()

        if not order:
            return "订单不存在", 404
        if order["status"] != "pending":
            return "订单已处理", 400

        # 事务：更新状态 + 增加余额
        conn.execute("UPDATE recharge_orders SET status = 'approved', approved_by = ?, updated_at = datetime('now') WHERE id = ?",
                      (session["user_id"], order["id"]))
        conn.execute("UPDATE users SET balance_cents = balance_cents + ? WHERE id = ?",
                      (order["amount_cents"], order["user_id"]))
        conn.commit()
        logger.info("充值审批通过: order=%d user=%s amount_cents=%d", order["id"], order["user_id"], order["amount_cents"])
    except Exception:
        conn.rollback()
        logger.exception("审批失败")
        return "审批失败", 500
    finally:
        conn.close()

    return redirect("/profile")


# =============================================================
# 退出（POST，CSRF 保护）
# =============================================================
@main_bp.route("/logout", methods=["POST"])
def logout():
    username = session.get("username", "unknown")
    session.clear()
    logger.info("用户 '%s' 已退出", username)
    return redirect("/login")


# =============================================================
# 上传 & 文件服务（不变）
# =============================================================
@main_bp.route("/upload", methods=["GET", "POST"])
def upload():
    if "user_id" not in session:
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
    from flask import send_from_directory, abort as f_abort
    from app.upload_handler import UPLOAD_DIR
    safe_name = os.path.basename(filename)
    file_path = UPLOAD_DIR / safe_name
    if not file_path.exists():
        f_abort(404)

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
