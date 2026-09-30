# syntax=docker/dockerfile:1
#
# В отличие от остальных сервисов проекта — не multi-stage C++ сборка,
# просто готовый образ nginx + статические файлы. Ничего собирать не нужно.
FROM nginx:1.27-alpine

COPY nginx.conf /etc/nginx/nginx.conf
COPY site/ /usr/share/nginx/html/

EXPOSE 80
