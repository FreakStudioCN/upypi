#!/bin/sh
set -e

CERT=/tls/cert.crt
KEY=/tls/cert.key

# ========= 自动生成自签名证书 =========
if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
    echo "TLS cert not found, generating self-signed certificate..."

    mkdir -p /tls

    openssl req -x509 -nodes -days 3650 \
        -newkey rsa:2048 \
        -keyout "$KEY" \
        -out "$CERT" \
        -subj "/CN=localhost"
fi

# ========= 启动服务 =========
nginx
exec python3 -m gunicorn -w 2 -k gthread --threads 4 -b 127.0.0.1:5000 app:app
