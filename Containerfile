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

EXPOSE 80
