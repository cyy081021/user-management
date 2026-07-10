"""
数据库模块 — SQLite 操作、迁移、统一数据源
"""
import sqlite3
import os
import logging
import math
from decimal import Decimal, InvalidOperation
from werkzeug.security import generate_password_hash

logger = logging.getLogger(__name__)

DB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
DB_PATH = os.path.join(DB_DIR, "users.db")


def get_db():
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _migrate_users_table(cursor):
    """v5.3→v6.1 迁移：添加 role、balance_cents，转换旧 balance"""
    cursor.execute("PRAGMA table_info(users)")
    cols = {row["name"] for row in cursor.fetchall()}

    alter = []

    if "role" not in cols:
        cursor.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")
        alter.append("role")

    if "balance_cents" not in cols:
        cursor.execute("ALTER TABLE users ADD COLUMN balance_cents INTEGER NOT NULL DEFAULT 0")
        alter.append("balance_cents")

    if "old_balance_migrated" not in cols:
        cursor.execute("ALTER TABLE users ADD COLUMN old_balance_migrated INTEGER NOT NULL DEFAULT 0")
        alter.append("old_balance_migrated")

    if alter:
        logger.info("迁移: 新增字段 %s", ", ".join(alter))

    # 将旧 balance(REAL) 迁移到 balance_cents(INTEGER)
    rows = cursor.execute(
        "SELECT id, balance, old_balance_migrated FROM users WHERE old_balance_migrated = 0"
    ).fetchall()

    for row in rows:
        raw = row["balance"]
        cents = 0
        if raw is not None and isinstance(raw, (int, float)) and math.isfinite(raw) and raw > 0:
            try:
                cents = int(Decimal(str(raw)) * 100)
            except (InvalidOperation, ValueError):
                cents = 0
        cursor.execute(
            "UPDATE users SET balance_cents = ?, old_balance_migrated = 1 WHERE id = ?",
            (cents, row["id"]),
        )

    if rows:
        logger.info("迁移: 已转换 %d 条旧余额记录为 balance_cents", len(rows))
    else:
        logger.info("迁移: 无需转换旧余额")


def _create_orders_table(cursor):
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
    # 事务最早版本不做幂等索引以外的工作


def init_db(admin_pw=None, alice_pw=None):
    """初始化/迁移数据库，用事务包裹"""
    conn = get_db()
    try:
        cursor = conn.cursor()

        # 1. 基础 users 表
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

        # 2. 迁移
        _migrate_users_table(cursor)

        # 3. 充值订单表
        _create_orders_table(cursor)

        # 4. 更新默认用户密码（哈希）和角色
        if admin_pw:
            hashed = generate_password_hash(admin_pw)
            cursor.execute(
                "INSERT OR IGNORE INTO users (username, password, email, phone, role) VALUES (?, ?, ?, ?, ?)",
                ("admin", hashed, "admin@example.com", "13800138000", "admin"),
            )
            cursor.execute(
                "UPDATE users SET password = ?, role = 'admin' WHERE username = 'admin'",
                (hashed,),
            )

        if alice_pw:
            hashed = generate_password_hash(alice_pw)
            cursor.execute(
                "INSERT OR IGNORE INTO users (username, password, email, phone, role) VALUES (?, ?, ?, ?, ?)",
                ("alice", hashed, "alice@example.com", "13900139001", "user"),
            )
            cursor.execute(
                "UPDATE users SET password = ? WHERE username = 'alice'",
                (hashed,),
            )

        conn.commit()
        logger.info("数据库初始化/迁移完成")
    except Exception:
        logger.exception("数据库初始化失败，回滚")
        conn.rollback()
        raise
    finally:
        conn.close()
