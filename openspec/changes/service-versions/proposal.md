# Proposal

## Why

Чтобы узнать, какая сборка веба и сервисов сейчас открыта, нужно идти на хост
(`tags.env`, `docker ps`). При ручной проверке тест-задачи и после выката
хочется видеть это прямо на странице. Гейтвей получает сводку версий
`GET /api/versions` (change `service-versions` в wallet-gateway), и веб должен её
показать.

## What Changes

- Внутренний `/version` веба получает поля `build` (тег образа из
  `--build-arg APP_BUILD`, без него — `<VERSION>-dev`) и `started_at` (время
  запуска контейнера).
- Тот же файл отдаётся по публичному пути `/version.json`. Гейтвей отправляет
  такой путь в wallet-web как обычную статику, поэтому версию веба видно и без
  входа.
- Release-workflow передаёт в сборку `APP_BUILD`.
- В правом нижнем углу каждого экрана появляется мелкий бейдж `web <build>`. По
  наведению (на телефоне — по тапу) открывается подсказка:
  - у роли `admin` — таблица всех сервисов из `GET /api/versions`: сервис, сборка,
    коммит, время запуска; у не ответивших — «нет ответа»;
  - у остальных и на экране входа — только строка веба из `/version.json`.

## Capabilities

### New Capabilities
- `version-badge`: бейдж версии в углу экрана и подсказка со сводкой версий
  сервисов.

### Modified Capabilities
- `static-hosting`: новое требование «Версия сборки» — `/version` и
  `/version.json` с `build`/`started_at`. Раньше версия веба в спеке не была
  описана.

## Impact

- `Containerfile` (`ARG APP_BUILD`, скрипт в `/docker-entrypoint.d/`, который при
  старте проставляет `started_at`), `nginx.conf` (`location = /version.json`),
  `.github/workflows/release.yml`.
- `site/app.js` (бейдж и подсказка), `site/style.css`, `site/index.html`
  (контейнер бейджа), `README.md`.
- Зависит от `GET /api/versions` гейтвея и от `build`/`started_at` в `/version`
  остальных сервисов (их change `service-versions`). Пока они не выкачены, таблица
  показывает «—» в пустых полях или «нет ответа».
