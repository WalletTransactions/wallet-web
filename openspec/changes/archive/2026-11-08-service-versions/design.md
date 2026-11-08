# Design

## Context

- Общие решения о полях `/version` (`build` — тег образа через `APP_BUILD`,
  `started_at` — время запуска) и о сводке `GET /api/versions` описаны в
  `wallet-gateway/openspec/changes/service-versions/design.md` (D1–D5). Здесь —
  только веб.
- Сейчас `/etc/nginx/version.json` пишется один раз при сборке образа
  (`Containerfile`, `RUN printf …`) и отдаётся nginx-ом по `location = /version`.
  Снаружи этот путь недоступен: на `/version` гейтвей отвечает сам.
- Образ — `nginx:1.27-alpine`. Его `/docker-entrypoint.sh` перед запуском nginx
  выполняет скрипты `/docker-entrypoint.d/*.sh`. Файловая система контейнера
  доступна на запись (в compose нет `read_only`).
- `site/app.js` перерисовывает `#app` через `innerHTML`. `currentUser` выставляется
  после `/auth/me`; экран входа — `renderLogin()`.

## Goals / Non-Goals

**Goals:**
- Версия веба видна всем и без входа; полная сводка — только админу.
- Бейдж не мешает работе и не зависит от перерисовок экранов.

**Non-Goals:**
- Сравнение версий, подсветка устаревших сборок, уведомления о выкате.
- Версия Android-клиента.

## Decisions

### D1. `started_at` пишет скрипт при старте контейнера
При сборке в образ кладётся шаблон `/etc/nginx/version.json.in` с `build`,
`git_commit`, `version` и меткой `@STARTED_AT@`. Скрипт
`/docker-entrypoint.d/40-version-json.sh` на каждом старте делает
`sed "s/@STARTED_AT@/$(date -u +%Y-%m-%dT%H:%M:%SZ)/" … > /etc/nginx/version.json`.
Файл пишется из шаблона заново на каждом старте, поэтому после
`docker restart` время обновляется, хотя слой контейнера сохранился.
*Альтернатива* — nginx `ssi`/`$time_iso8601`. Это время запроса, а не запуска;
отклонено.

### D2. Публичный `/version.json`, а не новый путь в гейтвее
nginx получает `location = /version.json` с тем же `alias` и
`Cache-Control: no-store`. Гейтвей отправляет `/version.json` в wallet-web как
статику, так что правка гейтвея не нужна. Свой `/version` гейтвея остаётся
нетронутым.
*Альтернатива* — брать версию веба из `/api/versions`. Но это только для админа,
а бейдж нужен всем и на экране входа.

### D3. Бейдж живёт вне `#app`
В `index.html` рядом с `#app` добавляется `<button id="version-badge" hidden>`.
`app.js` при загрузке один раз запрашивает `/version.json`, заполняет бейдж и
показывает его. Перерисовки экранов бейдж не трогают. Роль берётся из
`currentUser` в момент открытия подсказки, поэтому после входа или выхода ничего
переподписывать не нужно.

### D4. Своя подсказка, а не `title`
`title` не открывается тапом и не умеет таблицу. Подсказка — `div` над бейджем
(`position: fixed`, `bottom/right` от бейджа). Открытие: `mouseenter`/`focus`,
на тач-устройствах — `click`. Закрытие: `mouseleave` с бейджа и подсказки,
`Esc`, клик вне подсказки (`document`, фаза capture, событие не гасится). Бейдж —
`<button>`, поэтому доступен с клавиатуры.

### D5. Положение над таббаром
`@media (max-width: 720px)`: `body:has(.mobile-tabbar) #version-badge` получает
`bottom` = высота таббара + 4px. `:has` уже используется в `style.css`.

### Правки в других сервисах
- wallet-gateway: `GET /api/versions` — его change `service-versions`.
- Остальные сервисы: `build`/`started_at` в `/version` — их change
  `service-versions`. Веб готов к ответам без этих полей и показывает «—».

## Risks / Trade-offs

- [Бейдж перекрывает кнопку в правом нижнем углу какого-то экрана] → мелкий
  шрифт, `pointer-events` только на самом бейдже. Ручная проверка всех экранов
  на 1280 и 375 — в tasks.
- [Сводка медленная (~2 с при зависшем сервисе)] → «Загрузка…» сразу. Ответ,
  пришедший после закрытия подсказки, отбрасывается.
