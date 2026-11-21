'use strict';
// Форма «+ Операция» на «Списке операций» (change add-manual-operation).
// Живой контур — для самой записи и справочника; негативные ответы сервера,
// category_kind и долговой кошелёк подменяются через page.route.

const { test, before, after } = require('node:test');
const assert = require('node:assert');
const lib = require('../lib');

let browser;
let ctx;
let seed;
let skipReason = '';

before(async () => {
  await lib.start();
  browser = await lib.launch();
  try {
    ctx = await lib.newUserContext(browser);
    seed = await lib.seedLedger(ctx.context);
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

function today() {
  const d = new Date();
  const p = (n) => String(n).padStart(2, '0');
  return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate());
}

// Считает запросы /sync/push (тела — в pushes); handler(route, n) — необязательная подмена.
async function trackPushes(page, handler) {
  const pushes = [];
  await page.route('**/sync/push', (route) => {
    pushes.push(JSON.parse(route.request().postData()));
    if (handler) return handler(route, pushes.length);
    return route.continue();
  });
  return pushes;
}

async function openForm(page) {
  await page.goto('/');
  await page.locator('.nav-item[data-view="ops"]').click();
  await page.locator('#ops-add-btn').click();
  await page.locator('#op-amount').waitFor();
}

async function fill(page, { type, amount, wallet, category, comment }) {
  if (type === 'income') await page.locator('[data-op-type="income"]').click();
  if (amount !== undefined) await page.locator('#op-amount').fill(amount);
  if (wallet) await page.locator('#op-wallet').selectOption(wallet);
  if (category) await page.locator('#op-category').selectOption(category);
  if (comment !== undefined) await page.locator('#op-comment').fill(comment);
}

async function options(page, selector) {
  return (await page.locator(selector + ' option').allTextContents()).map((s) => s.trim());
}

// Подмена справочника: category_kind у статей и долговой кошелёк.
async function mockAccounts(page) {
  await page.route('**/api/reports/accounts*', async (route) => {
    const res = await route.fetch();
    const body = await res.json();
    body.accounts.forEach((a) => {
      if (a.kind === 'wallet') a.category_kind = 2;
      else if (a.uuid === seed.expense.uuid) a.category_kind = 0;
      else if (a.uuid === seed.income.uuid) a.category_kind = 1;
    });
    const wallet = body.accounts.find((a) => a.uuid === seed.wallet.uuid);
    body.accounts.push(Object.assign({}, wallet, {
      uuid: lib.uuid(), name: 'E2E Долг', counterparty_uuid: lib.uuid(),
    }));
    await route.fulfill({ response: res, json: body });
  });
}

test('форма открывается с умолчаниями и закрывается без записи', async (t) => {
  if (skipReason) return t.skip(skipReason);
  const page = await ctx.context.newPage();
  const pushes = await trackPushes(page);
  await openForm(page);
  assert.ok(await page.getByText('Новая операция').isVisible());
  assert.ok(await page.locator('[data-op-type="expense"].active').isVisible(), 'тип по умолчанию «Расход»');
  assert.strictEqual(await page.locator('#op-date').inputValue(), today());
  assert.match(await page.locator('#op-time').inputValue(), /^\d{2}:\d{2}$/);
  assert.strictEqual(await page.locator('#op-amount').inputValue(), '');
  assert.ok(await page.locator('#op-save-btn').isDisabled(), 'без суммы «Записать» неактивна');

  await page.locator('#op-amount').fill('10');
  await page.locator('#op-cancel-btn').click();
  assert.ok(!(await page.locator('#op-dialog').evaluate((d) => d.open)), 'после «Отмена» диалог закрыт');

  await page.locator('#ops-add-btn').click();
  await page.locator('#op-amount').waitFor();
  assert.strictEqual(await page.locator('#op-amount').inputValue(), '', 'новая форма пустая');
  await page.keyboard.press('Escape');
  assert.ok(!(await page.locator('#op-dialog').evaluate((d) => d.open)), 'Esc закрывает диалог');
  assert.strictEqual(pushes.length, 0, 'закрытие ничего не записывает');
  await page.close();
});

test('кошельки без долговых, статьи — по типу операции', async (t) => {
  if (skipReason) return t.skip(skipReason);
  const page = await ctx.context.newPage();
  await mockAccounts(page);
  await openForm(page);

  const wallets = await options(page, '#op-wallet');
  assert.ok(wallets.some((w) => w.startsWith(seed.wallet.name)), 'свой кошелёк есть');
  assert.ok(!wallets.some((w) => w.includes('E2E Долг')), 'долговой кошелёк не предлагается');

  let cats = await options(page, '#op-category');
  assert.ok(cats.includes(seed.expense.name));
  assert.ok(!cats.includes(seed.income.name), 'у расхода нет статей дохода');

  // Смена типа сбрасывает неподходящую статью и сохраняет сумму с комментарием.
  await fill(page, { amount: '12,5', category: seed.expense.uuid, comment: 'такси домой' });
  await page.locator('[data-op-type="income"]').click();
  cats = await options(page, '#op-category');
  assert.ok(cats.includes(seed.income.name));
  assert.ok(!cats.includes(seed.expense.name), 'у дохода нет статей расхода');
  assert.strictEqual(await page.locator('#op-category').inputValue(), '', 'статья сброшена');
  assert.strictEqual(await page.locator('#op-amount').inputValue(), '12,5');
  assert.strictEqual(await page.locator('#op-comment').inputValue(), 'такси домой');
  await page.close();
});

test('без category_kind в ответе предлагаются все статьи', async (t) => {
  if (skipReason) return t.skip(skipReason);
  const page = await ctx.context.newPage();
  await page.route('**/api/reports/accounts*', async (route) => {
    const res = await route.fetch();
    const body = await res.json();
    body.accounts.forEach((a) => { delete a.category_kind; });
    await route.fulfill({ response: res, json: body });
  });
  await openForm(page);
  for (const type of ['expense', 'income']) {
    await page.locator('[data-op-type="' + type + '"]').click();
    const cats = await options(page, '#op-category');
    assert.ok(cats.includes(seed.expense.name) && cats.includes(seed.income.name), type);
  }
  await page.close();
});

test('проверка полей: сумма, знаки после запятой, статья', async (t) => {
  if (skipReason) return t.skip(skipReason);
  const page = await ctx.context.newPage();
  await openForm(page);
  await fill(page, { wallet: seed.wallet.uuid, category: seed.expense.uuid });
  const save = page.locator('#op-save-btn');

  for (const bad of ['0', '0,00', 'abc', '-5']) {
    await page.locator('#op-amount').fill(bad);
    assert.ok(await save.isDisabled(), '«' + bad + '» не принимается');
  }
  await page.locator('#op-amount').fill('10,505');
  assert.ok(await save.isDisabled());
  assert.ok(await page.locator('#op-amount').evaluate((e) => e.classList.contains('invalid')), 'поле подсвечено');
  assert.match(await page.locator('#op-amount-hint').innerText(), /2 знаков/);

  await page.locator('#op-amount').fill('10,50');
  assert.ok(await save.isEnabled(), 'корректная сумма');
  assert.strictEqual(await page.locator('#op-currency').innerText(), 'USD');

  await page.locator('#op-category').selectOption('');
  assert.ok(await save.isDisabled(), 'без статьи нельзя');
  await page.close();
});

test('расход пишется «кошелёк → статья», доход — «статья → кошелёк»', async (t) => {
  if (skipReason) return t.skip(skipReason);
  const page = await ctx.context.newPage();
  const pushes = await trackPushes(page);
  await openForm(page);

  await fill(page, { amount: '450', wallet: seed.wallet.uuid, category: seed.expense.uuid, comment: 'e2e расход' });
  await page.locator('#op-save-btn').click();
  await page.locator('#ops-flash').getByText(/Записано:/).waitFor({ timeout: 15000 });
  let op = pushes[0].changes.operation[0];
  assert.strictEqual(op.acc_fr_uuid, seed.wallet.uuid);
  assert.strictEqual(op.acc_to_uuid, seed.expense.uuid);
  assert.strictEqual(op.amount, '450');
  assert.match(op.date, /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:00$/);
  assert.strictEqual(op.comment, 'e2e расход');

  await page.locator('#ops-add-btn').click();
  await page.locator('#op-amount').waitFor();
  assert.strictEqual(await page.locator('#op-wallet').inputValue(), seed.wallet.uuid, 'кошелёк по умолчанию — последний');
  await fill(page, { type: 'income', amount: '50000', category: seed.income.uuid });
  await page.locator('#op-save-btn').click();
  await page.waitForFunction(() => !document.getElementById('op-dialog').open);
  op = pushes[1].changes.operation[0];
  assert.strictEqual(op.acc_fr_uuid, seed.income.uuid);
  assert.strictEqual(op.acc_to_uuid, seed.wallet.uuid);
  assert.strictEqual(op.amount, '50000');
  assert.notStrictEqual(pushes[0].batch_id, pushes[1].batch_id, 'новая форма — новый batch_id');
  await page.close();
});

test('двойной клик — один запрос; повтор после сбоя сети — те же batch_id и uuid', async (t) => {
  if (skipReason) return t.skip(skipReason);
  const page = await ctx.context.newPage();
  const pushes = await trackPushes(page, (route, n) => (n === 1 ? route.abort('failed') : route.continue()));
  await openForm(page);
  await fill(page, { amount: '7', wallet: seed.wallet.uuid, category: seed.expense.uuid });

  await page.locator('#op-save-btn').dblclick();
  await page.getByText('Не удалось записать, попробуйте ещё раз').waitFor();
  assert.strictEqual(pushes.length, 1, 'двойной клик дал один запрос');
  assert.strictEqual(await page.locator('#op-amount').inputValue(), '7', 'поля сохранились');

  await page.locator('#op-save-btn').click();
  await page.waitForFunction(() => !document.getElementById('op-dialog').open);
  assert.strictEqual(pushes.length, 2);
  assert.strictEqual(pushes[0].batch_id, pushes[1].batch_id);
  assert.strictEqual(pushes[0].changes.operation[0].uuid, pushes[1].changes.operation[0].uuid);
  await page.close();
});

test('ошибки сервера: читатель, удалённая статья, 5xx — поля сохраняются', async (t) => {
  if (skipReason) return t.skip(skipReason);
  const page = await ctx.context.newPage();
  const answers = [
    { status: 403, json: { error: 'reader_cannot_write' } },
    { status: 409, json: { error: 'missing_reference' } },
    { status: 500, json: { error: 'boom' } },
  ];
  await trackPushes(page, (route, n) => (n <= answers.length ? route.fulfill(answers[n - 1]) : route.continue()));
  let accountsLoads = 0;
  await page.route('**/api/reports/accounts*', (route) => { accountsLoads++; return route.continue(); });
  await openForm(page);
  await fill(page, { amount: '9', wallet: seed.wallet.uuid, category: seed.expense.uuid, comment: 'мой коммент' });
  const save = page.locator('#op-save-btn');

  await save.click();
  await page.getByText('Вы читатель в этом леджере — добавлять операции нельзя').waitFor();
  assert.strictEqual(await page.locator('#op-amount').inputValue(), '9');

  const before409 = accountsLoads;
  await save.click();
  await page.getByText('Кошелёк или статья удалены — выберите другие').waitFor();
  assert.ok(accountsLoads > before409, 'справочник перезагружен');
  assert.strictEqual(await page.locator('#op-amount').inputValue(), '9');
  assert.strictEqual(await page.locator('#op-comment').inputValue(), 'мой коммент');
  // Подмена не удаляла статью на сервере, поэтому она осталась выбранной; выбираем снова на всякий случай.
  await page.locator('#op-category').selectOption(seed.expense.uuid);

  await save.click();
  await page.getByText('Не удалось записать, попробуйте ещё раз').waitFor();
  assert.ok(await page.locator('#op-dialog').evaluate((d) => d.open), 'форма осталась открытой');
  await page.close();
});

test('запись вне периода: «Записано… — вне выбранного периода», «Показать» открывает месяц', async (t) => {
  if (skipReason) return t.skip(skipReason);
  const page = await ctx.context.newPage();
  await openForm(page);
  await fill(page, { amount: '321', wallet: seed.wallet.uuid, category: seed.expense.uuid, comment: 'e2e в ленте' });
  await page.locator('#op-save-btn').click();

  const flash = page.locator('#ops-flash');
  await flash.getByText(/Записано:/).waitFor({ timeout: 15000 });
  assert.match(await flash.innerText(), /вне выбранного периода/);
  const to = await page.locator('#period-to').inputValue();
  assert.ok(to < today(), 'период по умолчанию кончается раньше сегодняшнего дня и сам не менялся');

  await page.locator('#op-flash-show-btn').click();
  const d = today();
  assert.strictEqual(await page.locator('#period-from').inputValue(), d.slice(0, 8) + '01');
  assert.ok((await page.locator('#period-to').inputValue()) >= d, 'период включает сегодня');
  assert.ok(await flash.isHidden(), 'строка с кнопкой исчезла');
  await page.locator('.ops-row', { hasText: 'e2e в ленте' }).first().waitFor({ timeout: 15000 });
  await page.close();
});

test('телефон 375px: кнопка в шапке при фильтре, форма — на весь экран без горизонтальной прокрутки', async (t) => {
  if (skipReason) return t.skip(skipReason);
  const phone = await lib.newUserContext(browser, lib.VIEWPORTS.phone);
  try {
    await lib.seedLedger(phone.context);
    const page = await phone.context.newPage();
    await page.goto('/');
    // Телефонная раскладка: вместо сайдбара — нижний таббар.
    await page.locator('.mobile-tab[data-tab="ops"]').click();
    await page.locator('#ops-add-btn').waitFor();
    await page.locator('#ops-search').fill('такси');
    const overflowPage = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    assert.ok(overflowPage <= 0, 'страница не шире экрана: ' + overflowPage);
    const btn = await page.locator('#ops-add-btn').boundingBox();
    assert.ok(btn && btn.x >= 0 && btn.x + btn.width <= 375, 'кнопка «+ Операция» целиком на экране');

    await page.locator('#ops-add-btn').click();
    await page.locator('#op-amount').waitFor();
    const box = await page.locator('#op-dialog').boundingBox();
    assert.ok(box.width >= 374 && box.height >= 700, 'лист на весь экран: ' + JSON.stringify(box));
    const overflowDialog = await page.locator('#op-dialog').evaluate((d) => d.scrollWidth - d.clientWidth);
    assert.ok(overflowDialog <= 0, 'в форме нет горизонтальной прокрутки: ' + overflowDialog);
    assert.ok(await page.locator('#op-save-btn').isVisible());
    if (process.env.E2E_SHOTS) await page.screenshot({ path: process.env.E2E_SHOTS + '/phone-form.png' });
  } finally {
    await phone.context.close();
  }
});

test('скриншот формы на десктопе (только при E2E_SHOTS)', async (t) => {
  if (skipReason) return t.skip(skipReason);
  if (!process.env.E2E_SHOTS) return t.skip('нужен E2E_SHOTS=<каталог>');
  const page = await ctx.context.newPage();
  await openForm(page);
  await fill(page, { amount: '10,505', wallet: seed.wallet.uuid });
  await page.screenshot({ path: process.env.E2E_SHOTS + '/desktop-form.png' });
  await page.close();
});

test('запись в применённом периоде — кнопки «Показать» нет, строка видна в ленте', async (t) => {
  if (skipReason) return t.skip(skipReason);
  const page = await ctx.context.newPage();
  await openForm(page);
  // Период «Этот месяц» включает сегодня.
  await page.locator('#op-cancel-btn').click();
  await page.locator('#period-presets [data-preset="month"], #period-presets [data-preset]').first().waitFor({ state: 'attached' });
  const d = today();
  await page.locator('#period-from').fill(d.slice(0, 8) + '01');
  await page.locator('#period-to').fill(d);
  await page.locator('#period-refresh-btn').click();

  await page.locator('#ops-add-btn').click();
  await page.locator('#op-amount').waitFor();
  await fill(page, { amount: '15', wallet: seed.wallet.uuid, category: seed.expense.uuid, comment: 'e2e в периоде' });
  await page.locator('#op-save-btn').click();
  await page.locator('#ops-flash').getByText(/Записано:/).waitFor({ timeout: 15000 });
  assert.ok(!(await page.locator('#ops-flash').innerText()).includes('вне выбранного периода'));
  assert.strictEqual(await page.locator('#op-flash-show-btn').count(), 0);
  await page.locator('.ops-row', { hasText: 'e2e в периоде' }).first().waitFor({ timeout: 15000 });
  await page.close();
});
