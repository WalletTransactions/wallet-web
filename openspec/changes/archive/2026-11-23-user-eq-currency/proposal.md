# Proposal

## Why

Issue [.github-private#19](https://github.com/WalletTransactions/.github-private/issues/19). Веб хранит валюту эквивалента только в
`localStorage` браузера (`eqCurrencyPreference`), а без неё показывает
USD. Другие клиенты этого выбора не видят: чат (MCP) на test ответил в
албанских леках. Решение владельца: выбор хранится в настройках пользователя на
сервере, веб его пишет, MCP читает.

## What Changes

- Выбор валюты в пикере «Настроек» и «Отчётов» сохраняется на сервере
  `PUT /api/settings {"eq_currency": "<ISO>"}` (wallet-api) и, как раньше, в
  `localStorage` — для мгновенной отрисовки до ответа справочника.
- Начальная валюта: `preferred_eq_currency` из `GET /api/reports/currencies`
  → `eqCurrencyPreference` из `localStorage` → `EUR` → первая валюта
  справочника (скрытые из эквивалента в запасном выборе пропускаются). Заглушка до загрузки справочника — сохранённый в
  `localStorage` код или `EUR` (вместо `USD`).
- Перенос: если на сервере ничего не выбрано, а в `localStorage` есть код из
  справочника леджера, веб один раз отправляет его на сервер.
- Ошибка `PUT` не мешает: выбор остаётся в браузере, отчёты пересчитываются,
  сообщение — «Не удалось сохранить валюту на сервере».

## Capabilities

### New Capabilities

Нет.

### Modified Capabilities

- `user-settings`: «Валюта эквивалента по умолчанию» — хранение на сервере.
- `reports-shell`: «Валюта эквивалента» — порядок выбора начальной валюты.

## Impact

- Код: `site/app.js` (`getEqCurrencyPreference`/`setEqCurrencyPreference`,
  загрузка справочника, пикеры), e2e-тесты.
- Зависит от wallet-api `user-eq-currency` (`PUT /api/settings`) и
  wallet-report `user-eq-currency` (`preferred_eq_currency`). Без них веб
  работает как раньше по `localStorage` (поле отсутствует, `PUT` — ошибка,
  выбор остаётся в браузере).
