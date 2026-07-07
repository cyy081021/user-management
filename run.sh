#!/bin/bash
# 用户管理系统启动脚本
# 用法：
#   ./run.sh              # HTTP 模式（Flask 开发服务器）
#   ./run.sh prod         # HTTP 模式（Gunicorn 生产）
#   ./run.sh https        # HTTPS 模式（Flask 开发服务器）
#   ./run.sh gunicorn-ssl # HTTPS 模式（Gunicorn 生产）

set -e

MODE="${1:-dev}"
APP_DIR="/root"
SSL_DIR="/root/ssl"

case "$MODE" in
  dev)
    echo "[启动] Flask 开发服务器 (HTTP)"
    cd "$APP_DIR"
    FLASK_DEBUG=0 FLASK_HTTPS=0 python3 app.py
    ;;
  prod)
    echo "[启动] Gunicorn 生产服务器 (HTTP)"
    mkdir -p /var/log/user-mgmt 2>/dev/null || true
    cd "$APP_DIR"
    gunicorn -c gunicorn_config.py app:app
    ;;
  https)
    echo "[启动] Flask 开发服务器 (HTTPS)"
    if [ ! -f "$SSL_DIR/cert.pem" ]; then
        echo "错误：SSL 证书不存在，请先生成证书" >&2
        exit 1
    fi
    cd "$APP_DIR"
    FLASK_DEBUG=0 FLASK_HTTPS=1 python3 app.py
    ;;
  gunicorn-ssl)
    echo "[启动] Gunicorn 生产服务器 (HTTPS)"
    if [ ! -f "$SSL_DIR/cert.pem" ]; then
        echo "错误：SSL 证书不存在，请先生成证书" >&2
        exit 1
    fi
    mkdir -p /var/log/user-mgmt 2>/dev/null || true
    cd "$APP_DIR"
    gunicorn -c gunicorn_config.py \
        --certfile="$SSL_DIR/cert.pem" \
        --keyfile="$SSL_DIR/key.pem" \
        app:app
    ;;
  *)
    echo "用法: $0 {dev|prod|https|gunicorn-ssl}"
    echo ""
    echo "  dev            Flask 开发服务器 (HTTP, 默认)"
    echo "  prod           Gunicorn 生产服务器 (HTTP)"
    echo "  https          Flask 开发服务器 (HTTPS)"
    echo "  gunicorn-ssl   Gunicorn 生产服务器 (HTTPS)"
    exit 1
    ;;
esac
