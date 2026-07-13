"""
数据库模块 — SQLite 操作、迁移、统一数据源

支持从 v5.3、v6.0、v6.1 升级，全新安装自动建表。
"""
import sqlite3
import os
import logging
import math
import re
from decimal import Decimal, InvalidOperation
from werkzeug.security import generate_password_hash

logger = logging.getLogger(__name__)

DB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
DB_PATH = os.path.join(DB_DIR, "users.db")

SQLITE_INT64_MAX = 9_223_372_036_854_775_807


def _resolve_path():
    override = os.environ.get("DATABASE_PATH", "")
    if override:
        return override, os.path.dirname(override)
    return DB_PATH, DB_DIR


_HASH_PREFIX_RE = re.compile(r"^(pbkdf2:|scrypt:|bcrypt:|argon2)")


def get_db(db_path=None):
    path = db_path or _resolve_path()[0]
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _table_columns(cursor, table):
    cursor.execute(f"PRAGMA table_info({table})")
    return {row["name"] for row in cursor.fetchall()}


# =============================================================
# 迁移引擎
# =============================================================

def migrate(db_path=None, admin_pw=None, alice_pw=None):
    """可重复执行的全量迁移（事务包裹），完成后同步默认账号密码"""
    if db_path:
        os.environ["DATABASE_PATH"] = db_path
    conn = get_db(db_path or _resolve_path()[0])
    try:
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
        """)
        current_ver = cursor.execute(
            "SELECT MAX(version) as v FROM schema_version"
        ).fetchone()["v"] or 0

        _step1_create_users(cursor, current_ver)
        _step2_add_columns(cursor, current_ver)
        _step3_migrate_passwords(cursor, current_ver)
        _step4_migrate_balance(cursor, current_ver)
        _step5_orders_table(cursor, current_ver)
        # 注意: _step6 已废弃，密码同步在 sync_seed_credentials 中完成
        _step7_record(cursor, current_ver)

        conn.commit()
        logger.info("数据库迁移完成 (version=7)")

        # 同步种子账号密码（不依赖 schema_version）
        _sync_seed_credentials_inner(cursor, admin_pw, alice_pw)
        conn.commit()
    except Exception:
        conn.rollback()
        logger.exception("数据库初始化失败，已回滚")
        raise
    finally:
        conn.close()


def _sync_seed_credentials_inner(cursor, admin_pw, alice_pw):
    """每次启动时同步默认 admin/alice 密码（内部，需调用方管理事务）"""
    if admin_pw:
        hashed = generate_password_hash(admin_pw)
        cursor.execute(
            "INSERT OR IGNORE INTO users (username, password, email, phone, role, password_migrated) "
            "VALUES (?, ?, ?, ?, 'admin', 1)",
            ("admin", hashed, "admin@example.com", "13800138000"),
        )
        cursor.execute(
            "UPDATE users SET password = ?, role = 'admin', password_migrated = 1 WHERE username = 'admin'",
            (hashed,),
        )
        logger.info("管理员密码已同步")

    if alice_pw:
        hashed = generate_password_hash(alice_pw)
        cursor.execute(
            "INSERT OR IGNORE INTO users (username, password, email, phone, role, password_migrated) "
            "VALUES (?, ?, ?, ?, 'user', 1)",
            ("alice", hashed, "alice@example.com", "13900139001"),
        )
        cursor.execute(
            "UPDATE users SET password = ?, password_migrated = 1 WHERE username = 'alice'",
            (hashed,),
        )
        logger.info("普通用户密码已同步")


def _step1_create_users(cursor, current_ver):
    if current_ver >= 1:
        return
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            phone TEXT,
            balance REAL DEFAULT 0.0
        )
    """)
    cursor.execute("INSERT OR REPLACE INTO schema_version (version) VALUES (1)")


def _step2_add_columns(cursor, current_ver):
    if current_ver >= 2:
        return
    cols = _table_columns(cursor, "users")
    defaults = [
        ("role", "TEXT NOT NULL DEFAULT 'user'"),
        ("balance_cents", "INTEGER NOT NULL DEFAULT 0"),
        ("old_balance_migrated", "INTEGER NOT NULL DEFAULT 0"),
        ("password_migrated", "INTEGER NOT NULL DEFAULT 0"),
    ]
    alterations = []
    for col_name, col_def in defaults:
        if col_name not in cols:
            try:
                cursor.execute(f"ALTER TABLE users ADD COLUMN {col_name} {col_def}")
                alterations.append(col_name)
            except Exception:
                logger.warning("添加字段 %s 失败（可能已存在）", col_name)
    if alterations:
        logger.info("迁移: 新增字段 %s", ", ".join(alterations))
    cursor.execute("INSERT OR REPLACE INTO schema_version (version) VALUES (2)")


def _step3_migrate_passwords(cursor, current_ver):
    if current_ver >= 3:
        return
    rows = cursor.execute(
        "SELECT id, username, password, password_migrated FROM users WHERE password_migrated = 0"
    ).fetchall()
    converted = 0
    for row in rows:
        pw = row["password"] or ""
        if _HASH_PREFIX_RE.match(pw):
            cursor.execute("UPDATE users SET password_migrated = 1 WHERE id = ?", (row["id"],))
            continue
        hashed = generate_password_hash(pw)
        cursor.execute(
            "UPDATE users SET password = ?, password_migrated = 1 WHERE id = ?",
            (hashed, row["id"]),
        )
        converted += 1
        logger.info("迁移: 用户 #%d 密码已哈希化", row["id"])
    if converted:
        logger.info("迁移: 已转换 %d 个明文密码为哈希", converted)
    cursor.execute("INSERT OR REPLACE INTO schema_version (version) VALUES (3)")


def _step4_migrate_balance(cursor, current_ver):
    """将旧 balance(REAL) 安全转换为 balance_cents(INTEGER 分)，不因异常数据中断"""
    if current_ver >= 4:
        return

    cols = _table_columns(cursor, "users")
    if "balance" not in cols:
        cursor.execute("UPDATE users SET balance_cents = 0, old_balance_migrated = 1 WHERE old_balance_migrated = 0")
        cursor.execute("INSERT OR REPLACE INTO schema_version (version) VALUES (4)")
        logger.info("迁移: 无旧 balance 列，balance_cents 设为 0")
        return

    rows = cursor.execute(
        "SELECT id, balance, old_balance_migrated FROM users WHERE old_balance_migrated = 0"
    ).fetchall()

    converted, zeroed = 0, 0
    for row in rows:
        raw = row["balance"]
        cents = 0
        reason = "ok"

        if raw is None:
            reason = "null"
            zeroed += 1
        elif isinstance(raw, (int, float)):
            if not math.isfinite(raw):
                reason = "not_finite"
                logger.warning("迁移: 用户 #%d 余额异常(nan/inf)，归零", row["id"])
                zeroed += 1
            elif raw <= 0:
                reason = "non_positive"
                logger.warning("迁移: 用户 #%d 余额为负或零，归零", row["id"])
                zeroed += 1
            else:
                try:
                    dec = Decimal(str(raw)) * 100
                    if dec > SQLITE_INT64_MAX:
                        reason = "overflow"
                        logger.warning("迁移: 用户 #%d 余额过大(1e+XX)，归零", row["id"])
                        zeroed += 1
                    elif dec < 0:
                        reason = "negative_cents"
                        zeroed += 1
                    else:
                        cents = int(dec)
                        if cents > SQLITE_INT64_MAX:
                            reason = "overflow"
                            logger.warning("迁移: 用户 #%d 余额越界，归零", row["id"])
                            cents = 0
                            zeroed += 1
                        else:
                            converted += 1
                except (InvalidOperation, ValueError, TypeError, OverflowError) as e:
                    reason = f"parse_error:{type(e).__name__}"
                    logger.warning("迁移: 用户 #%d 余额解析失败(%s)，归零", row["id"], type(e).__name__)
                    zeroed += 1
        else:
            reason = f"unexpected_type:{type(raw).__name__}"
            logger.warning("迁移: 用户 #%d 余额类型异常(%s)，归零", row["id"], type(raw).__name__)
            zeroed += 1

        cursor.execute(
            "UPDATE users SET balance_cents = ?, old_balance_migrated = 1 WHERE id = ?",
            (cents, row["id"]),
        )

    if converted or zeroed:
        logger.info("迁移: 余额转换完成 (正常=%d, 归零=%d)", converted, zeroed)
    cursor.execute("INSERT OR REPLACE INTO schema_version (version) VALUES (4)")


def _step5_orders_table(cursor, current_ver):
    if current_ver >= 5:
        return
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS recharge_orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            transaction_id TEXT UNIQUE NOT NULL,
            user_id INTEGER NOT NULL,
            amount_cents INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now')),
            approved_by INTEGER,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    cursor.execute("INSERT OR REPLACE INTO schema_version (version) VALUES (5)")


def _step7_record(cursor, current_ver):
    if current_ver >= 7:
        return
    cursor.execute("INSERT OR REPLACE INTO schema_version (version) VALUES (7)")


def init_db(admin_pw=None, alice_pw=None, db_path=None):
    """便捷入口：迁移 + 同步种子账号。密码参数为 None 时从环境变量读取"""
    if db_path:
        os.environ["DATABASE_PATH"] = db_path

    if admin_pw is None:
        admin_pw = os.environ.get("ADMIN_PASSWORD", "").strip() or None
    if alice_pw is None:
        alice_pw = os.environ.get("ALICE_PASSWORD", "").strip() or None

    migrate(admin_pw=admin_pw, alice_pw=alice_pw)
