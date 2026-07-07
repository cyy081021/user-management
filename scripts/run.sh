#!/bin/bash
# 用户管理系统启动脚本
# 用法：
#   ./scripts/run.sh              # HTTP 模式（Flask 开发服务器）
#   ./scripts/run.sh prod         # Gunicorn 生产（127.0.0.1 仅本地）
#   ./scripts/run.sh https        # HTTPS 模式（Flask 开发服务器）
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
SSL_CERT="$SSL_DIR/cert.example.pem"
SSL_KEY="$SSL_DIR/key.example.pem"

_check_ssl() {
    if [ ! -f "$SSL_CERT" ] || [ ! -f "$SSL_KEY" ]; then
        echo "错误：SSL 证书 ($SSL_CERT) 或私钥 ($SSL_KEY) 不存在" >&2
        echo "请先生成自签名证书："
        echo "  openssl req -x509 -newkey rsa:4096 -nodes \\"
        echo "    -out $SSL_CERT -keyout $SSL_KEY \\"
        echo "    -days 365 -subj '/C=CN/O=Dev/CN=localhost'"
        exit 1
    fi
}

case "$MODE" in
  dev)
    echo "[启动] Flask 开发服务器 (HTTP, 0.0.0.0:5000)"
    echo "[警告] 仅用于开发，生产请使用 ./scripts/run.sh prod"
    cd "$PROJECT_ROOT"
    FLASK_DEBUG=0 FLASK_HTTPS=0 python3 wsgi.py
    ;;
  prod)
    echo "[启动] Gunicorn 生产服务器 (127.0.0.1:5000，仅本地)"
    echo "[提示] 请配置 Nginx 反向代理对外提供服务（参考 deployment/nginx.conf.example）"
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
    _check_ssl
    echo "[启动] Flask 开发服务器 (HTTPS, 0.0.0.0:5000)"
    cd "$PROJECT_ROOT"
    FLASK_DEBUG=0 FLASK_HTTPS=1 \
      FLASK_SSL_CERT="$SSL_CERT" \
      FLASK_SSL_KEY="$SSL_KEY" \
      python3 wsgi.py
    ;;
  gunicorn-ssl)
    _check_ssl
    echo "[启动] Gunicorn 生产服务器 (HTTPS, 0.0.0.0:5000)"
    mkdir -p /var/log/user-mgmt 2>/dev/null || true
    cd "$PROJECT_ROOT"
    gunicorn \
        --bind 0.0.0.0:5000 \
        --workers "$(($(nproc) * 2 + 1))" \
        --timeout 30 \
        --certfile="$SSL_CERT" \
        --keyfile="$SSL_KEY" \
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
