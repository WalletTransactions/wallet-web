# Tasks

## 1. Вкладки экрана «Курсы валют»

- [ ] 1.1 `site/app.js`: `curTab` вместо `curCurrenciesOpen` (D1); `.ops-seg-group` «Валютные пары» / «Справочник валют» и главная кнопка вкладки; поиск — только на парах; `site/style.css` — строка вкладок на десктопе и до ~700px; проверка — в браузере (десктоп и ширина телефона) по сценариям «Открытие справочника валют», «Возврат к парам», «Режим „Посмотреть как клиент“» — Тест: [wallet-web#20](https://github.com/WalletTransactions/wallet-web/issues/20); код — aa9c4d6 (`0.1.2-rc.6`)

## 2. Модальное окно формы

- [ ] 2.1 `<dialog id="cur-currency-dialog">` в `#view-cur` (D2): заголовок «Новая валюта»/«Валюта <код>», закрытие Esc/«Отмена»/клик по затемнению, сброс `curCurrencyForm`; убрать `curCurrencyFormCapture`; закрытие в `switchReportsView` при уходе с `cur`; проверка — в браузере: открыть окно, «Назад» браузера на другую вкладку — страница кликабельна — Тест: [wallet-web#20](https://github.com/WalletTransactions/wallet-web/issues/20); код — aa9c4d6 (`0.1.2-rc.6`)
- [ ] 2.2 Дефолты и ввод (D7): точность `2`, ISO в верхний регистр без прыжка курсора, плейсхолдер символа = ISO, превью флага в поле ISO; проверка — сценарии «Новая валюта по умолчанию», «Код в нижнем регистре» — Тест: [wallet-web#20](https://github.com/WalletTransactions/wallet-web/issues/20); код — aa9c4d6 (`0.1.2-rc.6`)

## 3. Каталог и автозаполнение

- [ ] 3.1 `CURRENCY_PRESETS` и `datalist` у «ISO-код»/«Название» без валют справочника (D3); проверка — сценарий «Уже заведённая валюта» — Тест: [wallet-web#20](https://github.com/WalletTransactions/wallet-web/issues/20); код — aa9c4d6 (`0.1.2-rc.6`)
- [ ] 3.2 `curApplyPreset` с множеством `auto` (D3); проверка — сценарии «Ввод известного кода», «Ручное название сохраняется», «Смена кода»; при «Изменить» каталог не срабатывает — Тест: [wallet-web#20](https://github.com/WalletTransactions/wallet-web/issues/20); код — aa9c4d6 (`0.1.2-rc.6`)
- [ ] 3.3 `curFindPresetFlag` (сравнение по словам, приоритет — порядок подсказок) и подбор флага по приходу иконок (D4); проверка — на флагах test-контура сценарии «Ввод известного кода», «Флаг по названию страны», «Ручной флаг сохраняется»: `GEL`, `EUR` (`Flag Euro`), `HRK` (`Croatian flag`), `BAM` (`Bosnian flag`) подбираются верно, `BTC` без флага-иконки флаг не трогает. Сценарии «ISO-код важнее страны» и «Код не совпадает с частью слова» проверены 2026-11-03 прогоном функции в node на именах из seed.json плюс `American flag`/`Small flag`/`Rubble` — Тест: [wallet-web#20](https://github.com/WalletTransactions/wallet-web/issues/20); код — aa9c4d6 (`0.1.2-rc.6`)

## 4. Поиск иконки

- [ ] 4.1 Поле «Поиск флага», подписи под флагами, перерисовка только `#cur-icon-grid` (D5); `site/style.css` — ячейка с подписью; проверка — сценарий «Поиск флага» на десктопе и ширине телефона — Тест: [wallet-web#20](https://github.com/WalletTransactions/wallet-web/issues/20); код — aa9c4d6 (`0.1.2-rc.6`)

## 5. Ошибки в форме

- [ ] 5.1 `curCurrencyForm.errors`, `.invalid`, `.cur-field-error`, `.cur-form-error` (D6); проверка — сценарий «Пустые поля» — Тест: [wallet-web#20](https://github.com/WalletTransactions/wallet-web/issues/20); код — aa9c4d6 (`0.1.2-rc.6`)
- [ ] 5.2 `409` сохранения — под полем или блоком формы, ошибка удаления — над таблицей, без `alert`; проверка — сценарии «Код как у общей валюты» и «Удаление валюты кошелька» на test-контуре — Тест: [wallet-web#20](https://github.com/WalletTransactions/wallet-web/issues/20); код — aa9c4d6 (`0.1.2-rc.6`)

## 6. Документация

- [x] 6.1 `README.md`: раздел «Курсы валют» — вкладки, окно, каталог, поиск флага, ошибки; проверка — просмотр диффа — просмотрено 2026-11-03 (aa9c4d6)

## Workflow follow-up

- Архивировать после `currency-ui-tweaks`: этот change меняет его требования.
