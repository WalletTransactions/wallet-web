# syntax=docker/dockerfile:1
#
# В отличие от остальных сервисов проекта — не multi-stage C++ сборка,
# просто готовый образ nginx + статические файлы. Ничего собирать не нужно.
FROM nginx:1.27-alpine

COPY nginx.conf /etc/nginx/nginx.conf
COPY site/ /usr/share/nginx/html/

# Версия в адресах скриптов и стилей (index.html: /app.js -> /app.js?v=<хэш>).
# Браузер на телефоне сверял с сервером только саму страницу (GET / -> 304), а
# app.js/style.css брал из кэша, не спрашивая, — даже в новой вкладке, пока не
# очистить кэш вручную. Новый файл — новый хэш — новый адрес, который в кэше
# ещё не лежит. Хэш считается при сборке образа, руками ничего поднимать не
# нужно. Только свои файлы: vendor/ меняется вместе с версией библиотеки.
RUN cd /usr/share/nginx/html \
 && for f in app.js style.css; do \
      v=$(md5sum "$f" | cut -c1-10); \
      sed -i "s|\"/$f\"|\"/$f?v=$v\"|" index.html; \
    done \
 && grep -q 'app.js?v=' index.html && grep -q 'style.css?v=' index.html

# GET /version — те же поля service/version/build/git_commit/started_at, что
# у C++-сервисов (README google-auth, «Версия»): по version/git_commit smoke
# после выката сверяет, что поднялся именно выкатываемый тег. Версия — из
# VERSION, хэш и тег образа — снаружи (--build-arg GIT_COMMIT и APP_BUILD,
# так делает release.yml; без тега — `<VERSION>-dev`). started_at известен
# только при запуске контейнера: здесь — шаблон с меткой, настоящий
# version.json пишет entrypoint/40-version-json.sh. Файл вне корня статики,
# отдают его location = /version и = /version.json в nginx.conf. ARG — после
# тяжёлых слоёв, чтобы новый хэш не сбрасывал их кэш.
COPY VERSION /tmp/VERSION
ARG GIT_COMMIT=unknown
ARG APP_BUILD=
RUN v="$(tr -d '[:space:]' < /tmp/VERSION)" \
 && printf '{"build":"%s","git_commit":"%s","service":"wallet-web","started_at":"@STARTED_AT@","version":"%s"}\n' \
        "${APP_BUILD:-$v-dev}" "$GIT_COMMIT" "$v" > /etc/nginx/version.json.in \
 && rm /tmp/VERSION
COPY --chmod=0755 entrypoint/40-version-json.sh /docker-entrypoint.d/40-version-json.sh

EXPOSE 80
