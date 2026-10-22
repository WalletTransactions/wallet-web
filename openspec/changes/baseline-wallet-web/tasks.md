# Tasks

Изменение не меняет код: задачи — только сверка спецификаций с кодом и
живым стеком. Найденное несоответствие исправляется в спецификации, если неточна
она, или записывается в «Наблюдения» `design.md`, если расходится документ или
код ведёт себя неожиданно. Код в рамках этого изменения не правится.

## 1. Исходное состояние

- [ ] 1.1 Убедиться, что сверка идёт на коммите из `design.md` (`eafa93a`) или зафиксировать новый коммит в Context; проверка — `git log -1` совпадает с записанным
- [ ] 1.2 Стек поднят (`docker compose ... --env-file infra/db/.env`), веб открывается на десктопе и в эмуляции телефона; проверка — вход через Google проходит, открывается «Обзор»

## 2. Сверка по capability

Для каждой спецификации: каждый сценарий сопоставить с местом в `app.js` и
прогнать руками в браузере (десктоп и ширина телефона); тексты интерфейса
совпадают с кодом дословно.

- [ ] 2.1 `web-session` — `boot`, `apiFetch`/`apiJson`, `renderLogin`/`renderJoinLogin`/`renderError`, `acceptPendingInviteIfAny`, выход (`app.js:6469`)
- [ ] 2.2 `reports-shell` — `REPORTS_NAV`/`REPORTS_TITLES`/`REPORTS_BUILT_VIEWS`/`PERIOD_FREE_VIEWS`/`MOBILE_TABS`, `switchReportsView`, история и hash (`app.js:5800–5932`), период и валюта (`app.js:1239–1305`, `1508–1655`), `viewAsBannerHtml`, `renderReports`
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
- Решить, какие из Р11–Р23 оформлять отдельными changes; README-расхождения Р1–Р10 — одним change «README по коду».
