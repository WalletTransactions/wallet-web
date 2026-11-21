# Tasks

## 1. Разбиение длинных требований

- [x] 1.1 Дельты `ledger-icons`, `web-session`, `operations-list` написаны; проверить: `openspec validate split-long-requirements --strict` проходит без предупреждений о длине
- [x] 1.2 Архивировать change (спеки синхронизируются); проверить: `openspec validate --specs --strict` — ни одной спеки с предупреждением «very long», число требований выросло на 5 (ledger-icons +2, web-session +1, operations-list +2)

## Workflow follow-up

- Образ не меняется, rc и выкатка не нужны.
