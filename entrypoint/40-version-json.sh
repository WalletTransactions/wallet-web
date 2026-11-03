#!/bin/sh
# Время запуска контейнера в GET /version и /version.json (openspec/changes/
# service-versions, design D1). Запускается /docker-entrypoint.sh образа nginx
# перед nginx — на каждом старте, в том числе после `docker restart`: слой
# контейнера при перезапуске сохраняется, поэтому файл каждый раз пишется
# заново из шаблона, а не правится на месте. Ошибка здесь останавливает
# запуск контейнера (set -e у entrypoint nginx) — лучше упасть, чем отдать
# версию с чужим временем.
set -eu
started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
sed "s/@STARTED_AT@/${started_at}/" /etc/nginx/version.json.in > /etc/nginx/version.json
