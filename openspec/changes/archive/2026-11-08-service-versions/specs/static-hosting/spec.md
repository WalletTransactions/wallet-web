# Spec Delta

## ADDED Requirements

### Requirement: Версия сборки
`GET /version` (внутри сети контура) и `GET /version.json` (публично, через
гейтвей) SHALL отдавать один и тот же JSON `{"build", "git_commit", "service",
"started_at", "version"}` с заголовком `Cache-Control: no-store`. Значения:
`service` = `wallet-web`; `version` — из файла `VERSION`; `build` — из
`--build-arg APP_BUILD`, без него `<VERSION>-dev`; `git_commit` — из
`--build-arg GIT_COMMIT`, без него `unknown`; `started_at` — момент запуска
контейнера в ISO-8601 UTC (`2026-11-03T19:24:28Z`).

#### Scenario: Локальная сборка
- **WHEN** образ собран без `--build-arg` и запущен
- **THEN** `GET /version` отвечает `{"build":"<VERSION>-dev","git_commit":"unknown","service":"wallet-web","started_at":"<время запуска>","version":"<VERSION>"}`

#### Scenario: Через гейтвей
- **WHEN** браузер без входа запрашивает `GET /version.json` через wallet-gateway
- **THEN** ответ `200` с тем же JSON, что `/version` внутри контура, а не `index.html`

#### Scenario: Перезапуск контейнера
- **WHEN** контейнер wallet-web перезапущен без пересборки образа
- **THEN** `started_at` — время нового запуска, `build` и `git_commit` прежние
