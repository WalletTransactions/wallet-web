# Tasks

Изменение не меняет код: задачи — только сверка спецификаций с кодом и
живым стеком. Найденное несоответствие исправляется в спецификации, если неточна
она, или записывается в «Наблюдения» `design.md`, если расходится документ или
код ведёт себя неожиданно. Код в рамках этого изменения не правится.

## 1. Исходное состояние

- [x] 1.1 Убедиться, что сверка идёт на коммите из `design.md` (`eafa93a`) или зафиксировать новый коммит в Context; проверка — `git log -1` совпадает с записанным
- [x] 1.2 Стек поднят (`docker compose ... --env-file infra/db/.env`), веб открывается на десктопе и в эмуляции телефона; проверка — вход через Google проходит, открывается «Обзор»

## 2. Сверка по capability

Для каждой спецификации: каждый сценарий сопоставить с местом в `app.js` и
прогнать руками в браузере (десктоп и ширина телефона); тексты интерфейса
совпадают с кодом дословно.

Сверка по коду пройдена для всех 2.1–2.12 (2026-10-22): спецификации
поправлены, новые наблюдения — Р24–Р38. Пункты закрываются после прогона в
браузере.

Прогон в браузере — Chrome с `--remote-debugging-port` и скрипты
playwright-core через CDP (расширение Claude в Chrome недоступно). Отказы
сервера и необратимые действия (выход, приём приглашения) подменяются
`page.route`, `alert`/`confirm` перехватываются и сверяются дословно.
В 2.1 в браузере подтверждены Р12, Р13, Р27; в 2.2 — Р11, Р14, Р15, Р26.
Телефон — окно 390×844 (медиа-запрос `max-width: 720px`), касания не
эмулируются: жесты (свайп графика курса, Р35) остаются ручной проверкой.

- [x] 2.1 `web-session` — `boot`, `apiFetch`/`apiJson`, `renderLogin`/`renderJoinLogin`/`renderError`, `acceptPendingInviteIfAny`, выход (`app.js:6469`)
- [x] 2.2 `reports-shell` — `REPORTS_NAV`/`REPORTS_TITLES`/`REPORTS_BUILT_VIEWS`/`PERIOD_FREE_VIEWS`/`MOBILE_TABS`, `switchReportsView`, история и hash (`app.js:5800–5932`), период и валюта (`app.js:1239–1305`, `1508–1655`), `viewAsBannerHtml`, `renderReports`
- [ ] 2.3 `reports-overview` — `refreshPeriod`, `renderOverview*`, `goToMonthDetail`
- [ ] 2.4 `operations-list` — `refreshOperations`, `ops*`, бесконечная подгрузка, `goToOperationsFor*`
- [ ] 2.5 `spending-analytics` — `refreshStructure`/`renderTreemap`, `refreshDynamics`/`renderDynamics*`, `refreshCategories`/`renderCats*`, общие `buildBuckets`/`reportsWindowWithComparison`
- [ ] 2.6 `wallet-balances` — `refreshWalletBalances`, `buildWalletRows`, `renderWallet*`, `wireWalletEvents`
- [ ] 2.7 `currency-pairs` — `refreshCurrencyPairs`, `renderCur*`, `wireCurChart*`, `wireCurEvents`
- [ ] 2.8 `ledger-access` — `refreshAccess`, `renderAccessRoot`, `access*`, `wireAccessEvents`
- [ ] 2.9 `ledger-icons` — `refreshIcons`, `iconGridHtml`, `renderAdminIcons*`
- [ ] 2.10 `user-settings` — `renderSettings`, предпочтения валюты и даты, устройства (`loadSettingsDevices`, `wireRevoke*`), Telegram (`refreshTelegram`, `renderTelegram*`, `startTelegramPoll`), `wireDeleteAccount`
- [ ] 2.11 `admin-users` — `renderAdmin`/`renderAdminTable`, сортировка, `wireAdminForceLogout`, `wireAdminViewAs`
- [ ] 2.12 `static-hosting` — `nginx.conf`, `Containerfile`, `site/index.html`, `site/openapi.yaml`, CI; проверка — `docker build` и `curl -I` на `/`, `/app.js?v=…`, несуществующий путь

## 3. Итоговая проверка

- [ ] 3.1 `openspec validate baseline-wallet-web --strict`; проверка — change валиден
- [ ] 3.2 Перечитать «Наблюдения» `design.md` после сверки: новые добавлены, ошибочные убраны; проверка — у каждого Р-пункта есть файл:строка

## Workflow follow-up

- Заархивировать change (`/opsx:archive`) до применения `add-ai-expense-text`: спецификации переедут в `openspec/specs/`, и дельта ИИ ляжет поверх них.
- Решить, какие из Р11–Р23 и Р25–Р38 оформлять отдельными changes; README- и комментарии-расхождения Р1–Р10, Р24 — одним change «README по коду».
