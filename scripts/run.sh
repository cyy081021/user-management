#!/bin/bash
# 用户管理系统启动脚本
# 用法：
#   ./scripts/run.sh              # HTTP 模式（Flask 开发服务器）
#   ./scripts/run.sh prod         # Gunicorn 生产（127.0.0.1 仅本地）
#   ./scripts/run.sh https        # HTTPS 模式
#   ./scripts/run.sh gunicorn-ssl # Gunicorn 生产 + HTTPS

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# 加载环境变量（优先 project root 下的 .env）
ENV_FILE="$PROJECT_ROOT/.env"
if [ -f "$ENV_FILE" ]; then
    echo "[配置] 加载 $ENV_FILE"
    set -a
    source "$ENV_FILE"
    set +a
fi

MODE="${1:-dev}"
SSL_DIR="$PROJECT_ROOT/deployment/ssl"

case "$MODE" in
  dev)
    echo "[启动] Flask 开发服务器 (HTTP, 0.0.0.0:5000)"
    echo "[警告] 仅用于开发，生产请使用 ./scripts/run.sh prod"
    cd "$PROJECT_ROOT"
    FLASK_DEBUG=0 FLASK_HTTPS=0 python3 wsgi.py
    ;;
  prod)
    echo "[启动] Gunicorn 生产服务器 (127.0.0.1:5000，仅本地)"
    echo "[提示] 请配置 Nginx 反向代理对外提供服务"
    mkdir -p /var/log/user-mgmt 2>/dev/null || true
    cd "$PROJECT_ROOT"
    gunicorn \
        --bind 127.0.0.1:5000 \
        --workers "$(($(nproc) * 2 + 1))" \
        --timeout 30 \
        --access-logfile /var/log/user-mgmt/access.log \
        --error-logfile /var/log/user-mgmt/error.log \
        wsgi:app
    ;;
  https)
    echo "[启动] Flask 开发服务器 (HTTPS)"
    if [ ! -f "$SSL_DIR/cert.example.pem" ] && [ ! -f "$PROJECT_ROOT/ssl/cert.pem" ]; then
        echo "错误：SSL 证书不存在" >&2
        exit 1
    fi
    # 优先使用 deployment/ssl/，回退旧位置
    if [ ! -f "$SSL_DIR/cert.example.pem" ]; then
        cp "$PROJECT_ROOT/ssl/cert.pem" "$SSL_DIR/cert.example.pem"
        cp "$PROJECT_ROOT/ssl/key.pem" "$SSL_DIR/cert.example.pem" 2>/dev/null || true
    fi
    cd "$PROJECT_ROOT"
    FLASK_DEBUG=0 FLASK_HTTPS=1 python3 wsgi.py
    ;;
  gunicorn-ssl)
    echo "[启动] Gunicorn 生产服务器 (HTTPS, 0.0.0.0:5000)"
    if [ ! -f "$SSL_DIR/cert.example.pem" ] && [ ! -f "$PROJECT_ROOT/ssl/cert.pem" ]; then
        echo "错误：SSL 证书不存在" >&2
        exit 1
    fi
    mkdir -p /var/log/user-mgmt 2>/dev/null || true
    cd "$PROJECT_ROOT"
    gunicorn \
        --bind 0.0.0.0:5000 \
        --workers "$(($(nproc) * 2 + 1))" \
        --timeout 30 \
        --certfile="$SSL_DIR/cert.example.pem" \
        --keyfile="$SSL_DIR/cert.example.pem" \
        --access-logfile /var/log/user-mgmt/access.log \
        --error-logfile /var/log/user-mgmt/error.log \
        wsgi:app
    ;;
  *)
    echo "用法: $0 {dev|prod|https|gunicorn-ssl}"
    echo ""
    echo "  dev            开发服务器 (HTTP, 0.0.0.0)"
    echo "  prod           生产 (127.0.0.1，需 Nginx 反代)"
    echo "  https          HTTPS 开发服务器"
    echo "  gunicorn-ssl   HTTPS 生产服务器"
    exit 1
    ;;
esac
