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

# 用于测试覆盖：设置此环境变量可指定数据库路径
def _resolve_path():
    """每次调用时动态检查环境变量"""
    override = os.environ.get("DATABASE_PATH", "")
    if override:
        return override, os.path.dirname(override)
    return DB_PATH, DB_DIR

_HASH_PREFIX_RE = re.compile(r"^(pbkdf2:|scrypt:|bcrypt:|argon2)")


def get_db(db_path=None):
    """获取数据库连接，支持临时路径"""
    path = db_path or _resolve_path()[0]
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _table_columns(cursor, table):
    """返回表的所有列名集合"""
    cursor.execute(f"PRAGMA table_info({table})")
    return {row["name"] for row in cursor.fetchall()}


# =============================================================
# 迁移引擎
# =============================================================

def migrate(db_path=None):
    """可重复执行的全量迁移，事务包裹"""
    if db_path:
        os.environ["DATABASE_PATH"] = db_path
    conn = get_db(db_path or _resolve_path()[0])
    try:
        cursor = conn.cursor()

        # 0. 创建 schema_version 表
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
        """)
        current_ver = cursor.execute(
            "SELECT MAX(version) as v FROM schema_version"
        ).fetchone()["v"] or 0

        # 1. Create or upgrade users table
        _step1_create_users(cursor, current_ver)
        # 2. Add new columns
        _step2_add_columns(cursor, current_ver)
        # 3. Migrate old plaintext passwords
        _step3_migrate_passwords(cursor, current_ver)
        # 4. Migrate old balance to balance_cents
        _step4_migrate_balance(cursor, current_ver)
        # 5. Create recharge_orders
        _step5_orders_table(cursor, current_ver)
        # 6. Update default accounts
        _step6_update_defaults(cursor, current_ver)
        # 7. Record version
        cursor.execute("INSERT OR REPLACE INTO schema_version (version) VALUES (7)")
        conn.commit()
        logger.info("数据库迁移完成 (version=7)")
    except Exception:
        conn.rollback()
        logger.exception("数据库迁移失败，已回滚")
        raise
    finally:
        conn.close()


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

    alterations = []
    defaults = [
        ("role", "TEXT NOT NULL DEFAULT 'user'"),
        ("balance_cents", "INTEGER NOT NULL DEFAULT 0"),
        ("old_balance_migrated", "INTEGER NOT NULL DEFAULT 0"),
        ("password_migrated", "INTEGER NOT NULL DEFAULT 0"),
    ]
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
    """将 v5/v6.0 明文密码转换为 Werkzeug 哈希"""
    if current_ver >= 3:
        return
    rows = cursor.execute(
        "SELECT id, username, password, password_migrated FROM users WHERE password_migrated = 0"
    ).fetchall()

    converted = 0
    for row in rows:
        pw = row["password"] or ""
        # 已经是哈希的不需要转换
        if _HASH_PREFIX_RE.match(pw):
            cursor.execute(
                "UPDATE users SET password_migrated = 1 WHERE id = ?",
                (row["id"],),
            )
            continue

        # 明文 → 哈希
        hashed = generate_password_hash(pw)
        cursor.execute(
            "UPDATE users SET password = ?, password_migrated = 1 WHERE id = ?",
            (hashed, row["id"]),
        )
        converted += 1
        logger.info("迁移: 用户 '%s' 密码已哈希化", row["username"])

    if converted:
        logger.info("迁移: 已转换 %d 个明文密码为哈希", converted)
    cursor.execute("INSERT OR REPLACE INTO schema_version (version) VALUES (3)")


def _step4_migrate_balance(cursor, current_ver):
    """将旧 balance(REAL) 安全转换为 balance_cents(INTEGER 分)"""
    if current_ver >= 4:
        return

    cols = _table_columns(cursor, "users")

    # v5.3 没有 balance 列，直接归零
    if "balance" not in cols:
        cursor.execute("UPDATE users SET balance_cents = 0, old_balance_migrated = 1 WHERE old_balance_migrated = 0")
        cursor.execute("INSERT OR REPLACE INTO schema_version (version) VALUES (4)")
        logger.info("迁移: 无旧 balance 列，balance_cents 设为 0")
        return

    rows = cursor.execute(
        "SELECT id, balance, balance_cents, old_balance_migrated FROM users WHERE old_balance_migrated = 0"
    ).fetchall()

    converted = 0
    skipped = 0
    for row in rows:
        raw = row["balance"]
        cents = 0
        if raw is not None and isinstance(raw, (int, float)):
            if math.isfinite(raw) and raw > 0:
                try:
                    cents = int(Decimal(str(raw)) * 100)
                    if cents < 0:
                        logger.warning("迁移: 用户 #%d 余额为负(%.2f)，归零", row["id"], raw)
                        cents = 0
                except (InvalidOperation, ValueError):
                    logger.warning("迁移: 用户 #%d 余额解析失败(%.2f)，归零", row["id"], raw)
                    cents = 0
            else:
                logger.warning("迁移: 用户 #%d 余额异常(nan/inf)，归零", row["id"])
        else:
            skipped += 1

        cursor.execute(
            "UPDATE users SET balance_cents = ?, old_balance_migrated = 1 WHERE id = ?",
            (cents, row["id"]),
        )
        converted += 1

    if converted or skipped:
        logger.info("迁移: 已转换 %d 条余额记录 (跳过 %d)", converted, skipped)
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


def _step6_update_defaults(cursor, current_ver):
    """使用环境变量更新 admin/alice 密码"""
    if current_ver >= 6:
        return

    admin_pw = os.environ.get("ADMIN_PASSWORD", "").strip()
    alice_pw = os.environ.get("ALICE_PASSWORD", "").strip()

    if admin_pw:
        hashed = generate_password_hash(admin_pw)
        cursor.execute(
            "INSERT OR IGNORE INTO users (username, password, email, phone, role) VALUES (?, ?, ?, ?, ?)",
            ("admin", hashed, "admin@example.com", "13800138000", "admin"),
        )
        cursor.execute(
            "UPDATE users SET password = ?, role = 'admin', password_migrated = 1 WHERE username = 'admin'",
            (hashed,),
        )

    if alice_pw:
        hashed = generate_password_hash(alice_pw)
        cursor.execute(
            "INSERT OR IGNORE INTO users (username, password, email, phone, role) VALUES (?, ?, ?, ?, ?)",
            ("alice", hashed, "alice@example.com", "13900139001", "user"),
        )
        cursor.execute(
            "UPDATE users SET password = ?, password_migrated = 1 WHERE username = 'alice'",
            (hashed,),
        )

    cursor.execute("INSERT OR REPLACE INTO schema_version (version) VALUES (6)")


def init_db(admin_pw=None, alice_pw=None, db_path=None):
    """便捷入口：设置环境变量后执行迁移"""
    if admin_pw:
        os.environ["ADMIN_PASSWORD"] = admin_pw
    if alice_pw:
        os.environ["ALICE_PASSWORD"] = alice_pw
    if db_path:
        os.environ["DATABASE_PATH"] = db_path
    migrate()
