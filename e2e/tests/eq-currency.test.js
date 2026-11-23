'use strict';
// Валюта эквивалента на сервере (change user-eq-currency): начальная валюта из
// preferred_eq_currency / localStorage / EUR, перенос выбора на сервер, PUT
// /api/settings из пикеров «Отчётов» и «Настроек», ошибка PUT.
//
// Справочник — настоящий ответ контура, в нём подменяется только
// preferred_eq_currency (и при необходимости состав валют). PUT /api/settings
// подменён целиком: тест проверяет, что и когда уходит, а не сам wallet-api.

const { test, before, after } = require('node:test');
const assert = require('node:assert');
const lib = require('../lib');

const SAVE_ERROR = 'Не удалось сохранить валюту на сервере';

let browser;
let ctx;
let skipReason = '';

before(async () => {
  await lib.start();
  browser = await lib.launch();
  try {
    ctx = await lib.newUserContext(browser);
  } catch (e) {
    if (e instanceof lib.RegistrationClosed) skipReason = e.message;
    else throw e;
  }
});

after(async () => {
  if (ctx) await ctx.context.close();
  if (browser) await browser.close();
  await lib.stop();
});

// Открывает «Отчёты» с подменами. opts:
//   stored     — eqCurrencyPreference в localStorage (нет — пусто)
//   preferred  — preferred_eq_currency справочника (undefined — поле убрать, как у старого wallet-report)
//   only       — оставить в справочнике только эти коды
//   hidden     — коды с show_in_equivalent: false
//   putStatus  — ответ PUT /api/settings (по умолчанию 200)
// Возвращает {page, puts, eqRequests}: тела PUT и eq_currency запросов отчётов по порядку.
async function openReports(opts) {
  opts = opts || {};
  const page = await ctx.context.newPage();
  await page.addInitScript((stored) => {
    localStorage.clear();
    if (stored) localStorage.setItem('eqCurrencyPreference', stored);
  }, opts.stored || null);

  const puts = [];
  await page.route('**/api/settings', (route) => {
    const req = route.request();
    if (req.method() === 'PUT') {
      const body = JSON.parse(req.postData());
      puts.push(body);
      const status = opts.putStatus || 200;
      return route.fulfill({ status, json: status === 200 ? body : { error: 'internal' } });
    }
    return route.fulfill({ json: { eq_currency: opts.preferred === undefined ? null : opts.preferred } });
  });
  await page.route('**/api/reports/currencies*', async (route) => {
    const res = await route.fetch();
    const body = await res.json();
    if (opts.only) body.currencies = body.currencies.filter((c) => opts.only.includes(c.iso_code));
    if (opts.hidden) {
      body.currencies.forEach((c) => { c.show_in_equivalent = !opts.hidden.includes(c.iso_code); });
    }
    if (opts.preferred === undefined) delete body.preferred_eq_currency;
    else body.preferred_eq_currency = opts.preferred;
    await route.fulfill({ response: res, json: body });
  });

  const eqRequests = [];
  page.on('request', (req) => {
    const u = new URL(req.url());
    const eq = u.searchParams.get('eq_currency');
    if (u.pathname.startsWith('/api/reports/') && eq) eqRequests.push(eq);
  });

  await page.goto('/');
  await page.waitForSelector('#reports-title', { timeout: 15000 });
  // Справочник применён — список пикера заполнен.
  await page.waitForFunction(() => document.querySelectorAll('#currency-picker-list .currency-picker-row').length > 0,
    null, { timeout: 15000 });
  return { page, puts, eqRequests };
}

async function eqValue(page) {
  return page.locator('#eq-currency').inputValue();
}

async function stored(page) {
  return page.evaluate(() => localStorage.getItem('eqCurrencyPreference'));
}

// PUT уходит асинхронно — даём ему время дойти до подмены.
async function settle(page) {
  await page.waitForTimeout(500);
}

async function openReportsPicker(page) {
  if (!(await page.locator('#currency-picker-btn').isVisible())) await page.locator('#period-summary-btn').click();
  await page.locator('#currency-picker-btn').click();
}

test('заглушка до справочника — localStorage или EUR, не USD', async (t) => {
  if (skipReason) return t.skip(skipReason);
  const page = await ctx.context.newPage();
  await page.addInitScript(() => localStorage.clear());
  // Справочник не отвечает — на кнопке остаётся заглушка.
  await page.route('**/api/reports/currencies*', () => {});
  await page.goto('/');
  await page.waitForSelector('#reports-title', { timeout: 15000 });
  assert.strictEqual(await eqValue(page), 'EUR');
  assert.match(await page.locator('#currency-picker-display').innerText(), /EUR/);
  await page.close();
});

test('выбор с другого устройства: сервер EUR перекрывает USD из localStorage', async (t) => {
  if (skipReason) return t.skip(skipReason);
  const { page, puts, eqRequests } = await openReports({ stored: 'USD', preferred: 'EUR' });
  await page.waitForFunction(() => document.getElementById('eq-currency').value === 'EUR');
  assert.strictEqual(await stored(page), 'EUR', 'в localStorage записан EUR');
  await settle(page);
  assert.ok(eqRequests.lastIndexOf('EUR') > eqRequests.lastIndexOf('USD'), 'отчёты перезапрошены в EUR: ' + eqRequests);
  assert.deepStrictEqual(puts, [], 'серверный выбор обратно не отправляется');
  await page.close();
});

test('перенос выбора на сервер: null + RUB в localStorage — один PUT', async (t) => {
  if (skipReason) return t.skip(skipReason);
  const { page, puts } = await openReports({ stored: 'RUB', preferred: null });
  assert.strictEqual(await eqValue(page), 'RUB');
  await settle(page);
  assert.deepStrictEqual(puts, [{ eq_currency: 'RUB' }]);
  // «Обновить» перечитывает справочник, но перенос — один раз за загрузку страницы.
  if (!(await page.locator('#period-refresh-btn').isVisible())) await page.locator('#period-summary-btn').click();
  await page.locator('#period-refresh-btn').click();
  await settle(page);
  assert.strictEqual(puts.length, 1, 'повторного PUT нет');
  await page.close();
});

test('старый wallet-report без preferred_eq_currency — тоже перенос', async (t) => {
  if (skipReason) return t.skip(skipReason);
  const { page, puts } = await openReports({ stored: 'RUB' });
  assert.strictEqual(await eqValue(page), 'RUB');
  await settle(page);
  assert.deepStrictEqual(puts, [{ eq_currency: 'RUB' }]);
  await page.close();
});

test('ничего не выбрано: EUR, PUT не отправляется', async (t) => {
  if (skipReason) return t.skip(skipReason);
  const { page, puts } = await openReports({ preferred: null });
  assert.strictEqual(await eqValue(page), 'EUR');
  await settle(page);
  assert.deepStrictEqual(puts, []);
  await page.close();
});

test('валюты нет у леджера: USD → EUR, отчёты в EUR, без PUT', async (t) => {
  if (skipReason) return t.skip(skipReason);
  const { page, puts, eqRequests } = await openReports({ stored: 'USD', preferred: null, only: ['EUR', 'RUB'] });
  await page.waitForFunction(() => document.getElementById('eq-currency').value === 'EUR');
  await settle(page);
  assert.ok(eqRequests.lastIndexOf('EUR') > eqRequests.lastIndexOf('USD'), 'отчёты перезапрошены в EUR: ' + eqRequests);
  assert.deepStrictEqual(puts, [], 'автовыбор на сервер не уходит');
  await page.close();
});

test('автовыбор пропускает скрытые: AED скрыта, EUR, RUB → EUR', async (t) => {
  if (skipReason) return t.skip(skipReason);
  const { page } = await openReports({ stored: 'USD', preferred: null, only: ['AED', 'EUR', 'RUB'], hidden: ['AED'] });
  await page.waitForFunction(() => document.getElementById('eq-currency').value === 'EUR');
  await page.close();
});

test('автовыбор без EUR — первая нескрытая', async (t) => {
  if (skipReason) return t.skip(skipReason);
  const { page } = await openReports({ preferred: null, only: ['AED', 'GEL', 'RUB'], hidden: ['AED'] });
  await page.waitForFunction(() => document.getElementById('eq-currency').value === 'GEL');
  await page.close();
});

test('выбор в пикере «Отчётов» уходит PUT и в localStorage', async (t) => {
  if (skipReason) return t.skip(skipReason);
  const { page, puts, eqRequests } = await openReports({ stored: 'EUR', preferred: 'EUR' });
  await openReportsPicker(page);
  await page.locator('#currency-picker-list .currency-picker-row[data-iso="RUB"]').click();
  assert.ok(await page.locator('#currency-picker-list').isHidden(), 'список закрылся');
  await settle(page);
  assert.deepStrictEqual(puts, [{ eq_currency: 'RUB' }]);
  assert.strictEqual(await stored(page), 'RUB');
  assert.strictEqual(eqRequests[eqRequests.length - 1], 'RUB', 'отчёты перезапрошены в RUB');
  assert.ok(!(await page.locator('#currency-save-error').isVisible()), 'ошибки нет');
  await page.close();
});

test('«Отчёты»: сервер не сохранил — выбор остаётся, подпись под пикером', async (t) => {
  if (skipReason) return t.skip(skipReason);
  const { page, puts } = await openReports({ stored: 'EUR', preferred: 'EUR', putStatus: 500 });
  await openReportsPicker(page);
  await page.locator('#currency-picker-list .currency-picker-row[data-iso="RUB"]').click();
  await page.locator('#currency-save-error').waitFor({ state: 'visible', timeout: 5000 });
  assert.strictEqual(await page.locator('#currency-save-error').innerText(), SAVE_ERROR);
  assert.deepStrictEqual(puts, [{ eq_currency: 'RUB' }]);
  assert.strictEqual(await eqValue(page), 'RUB');
  assert.strictEqual(await stored(page), 'RUB');
  await page.close();
});

test('«Настройки»: смена валюты — PUT, флаг и код на кнопке', async (t) => {
  if (skipReason) return t.skip(skipReason);
  const { page, puts } = await openReports({ stored: 'RUB', preferred: 'RUB' });
  await page.locator('#settings-link-btn').click();
  await page.locator('#settings-currency-picker-btn').click();
  await page.locator('#settings-currency-picker-list .currency-picker-row[data-iso="EUR"]').click();
  assert.ok(await page.locator('#settings-currency-picker-list').isHidden(), 'список закрылся');
  assert.match(await page.locator('#settings-currency-picker-display').innerText(), /EUR/);
  await settle(page);
  assert.deepStrictEqual(puts, [{ eq_currency: 'EUR' }]);
  assert.strictEqual(await stored(page), 'EUR');
  assert.ok(!(await page.locator('#settings-currency-save-error').isVisible()), 'ошибки нет');
  await page.close();
});

test('«Настройки»: сервер не сохранил — выбор остаётся, подпись под пикером', async (t) => {
  if (skipReason) return t.skip(skipReason);
  const { page } = await openReports({ stored: 'RUB', preferred: 'RUB', putStatus: 500 });
  await page.locator('#settings-link-btn').click();
  await page.locator('#settings-currency-picker-btn').click();
  await page.locator('#settings-currency-picker-list .currency-picker-row[data-iso="EUR"]').click();
  await page.locator('#settings-currency-save-error').waitFor({ state: 'visible', timeout: 5000 });
  assert.strictEqual(await page.locator('#settings-currency-save-error').innerText(), SAVE_ERROR);
  assert.match(await page.locator('#settings-currency-picker-display').innerText(), /EUR/);
  assert.strictEqual(await stored(page), 'EUR');
  // Назад на «Отчёты»: сервер (RUB) не перекрывает выбор после неудачного PUT.
  await page.locator('#settings-back-btn').click();
  await page.waitForFunction(() => document.querySelectorAll('#currency-picker-list .currency-picker-row').length > 0);
  await settle(page);
  assert.strictEqual(await eqValue(page), 'EUR');
  await page.close();
});
