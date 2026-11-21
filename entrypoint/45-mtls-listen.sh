#!/bin/sh
# Слушатель nginx для взаимного TLS внутри контура (change add-internal-mtls, шаг 7, задача 7.5).
# Запускается /docker-entrypoint.sh образа nginx перед nginx, на каждом старте: пишет
# /etc/nginx/listen.conf (директивы server на порту 80) и /etc/nginx/health.conf (loopback-блок
# для healthcheck), которые подключает nginx.conf.
#
#   INTERNAL_MTLS не true (по умолчанию) — обычный `listen 80;`, health.conf пуст: поведение как
#   раньше.
#   INTERNAL_MTLS=true — `listen 80 ssl` с клиентским сертификатом от CA контура (рукопожатие без
#   сертификата не завершается), а healthcheck контейнера ходит на loopback-порт 8081, который
#   снаружи недоступен (design D5). Нет файлов сертификата — ошибка старта: лучше упасть, чем
#   молча отдавать статику без mTLS при включённом режиме.
set -eu

CERT=/etc/wallet-tls/tls.crt
KEY=/etc/wallet-tls/tls.key
CA=/etc/wallet-tls/ca.pem

if [ "${INTERNAL_MTLS:-}" = "true" ]; then
    for f in "$CERT" "$KEY" "$CA"; do
        [ -s "$f" ] || { echo "45-mtls-listen: INTERNAL_MTLS=true, но нет $f" >&2; exit 1; }
    done
    cat > /etc/nginx/listen.conf <<CONF
listen 80 ssl;
ssl_certificate $CERT;
ssl_certificate_key $KEY;
ssl_client_certificate $CA;
ssl_verify_client on;
ssl_protocols TLSv1.2 TLSv1.3;
CONF
    cat > /etc/nginx/health.conf <<'CONF'
server {
    listen 127.0.0.1:8081;
    access_log off;
    location = /healthz { return 200 "ok\n"; }
}
CONF
    echo "45-mtls-listen: mTLS включён (порт 80 требует клиентский сертификат, healthcheck — 127.0.0.1:8081)"
else
    echo 'listen 80;' > /etc/nginx/listen.conf
    : > /etc/nginx/health.conf
fi
