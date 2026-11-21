'use strict';
// Общий помощник записи (pushOperation): запись из карточки на экране «ИИ».
// ИИ подменён через page.route: статус включён, разбор отвечает not_expense, дальше
// карточка заполняется вручную («Заполнить вручную») — так проверяется именно
// запись, а не сам wallet-ai.

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

// Открывает «ИИ» с подменённым wallet-ai и доводит до пустой карточки.
async function openManualCard(page) {
  await page.route('**/api/ai/status', (route) =>
    route.fulfill({ json: { enabled: true, features: ['parse_expense'] } }));
  await page.route('**/api/ai/jobs', (route) =>
    route.fulfill({ status: 202, json: { job_id: 'e2e-job' } }));
  await page.route('**/api/ai/jobs/e2e-job**', (route) =>
    route.fulfill({ json: { status: 'done', result: { outcome: 'not_expense' } } }));
  await page.goto('/');
  await page.locator('.nav-item[data-view="ai"]').click();
  await page.locator('#ai-text').fill('что-то не про траты');
  await page.locator('#ai-parse-btn').click();
  await page.locator('#ai-manual-btn').click();
  await page.locator('#ai-amount').waitFor();
  await page.locator('#ai-amount').fill('100');
  await page.locator('#ai-wallet').selectOption(seed.wallet.uuid);
  await page.locator('#ai-category').selectOption(seed.expense.uuid);
}

test('device_required: один /auth/refresh и повтор с тем же batch_id', async (t) => {
  if (skipReason) return t.skip(skipReason);
  const page = await ctx.context.newPage();
  const pushes = [];
  let refreshed = 0;
  await page.route('**/sync/push', (route) => {
    pushes.push(JSON.parse(route.request().postData()));
    if (pushes.length === 1) return route.fulfill({ status: 403, json: { error: 'device_required' } });
    return route.continue();
  });
  await page.route('**/auth/refresh', (route) => {
    refreshed++;
    return route.continue();
  });
  await openManualCard(page);
  await page.locator('#ai-save-btn').click();
  await page.getByText(/Записано:/).waitFor({ timeout: 15000 });

  assert.strictEqual(pushes.length, 2, 'ровно один повтор');
  assert.strictEqual(refreshed, 1, 'ровно один /auth/refresh');
  assert.strictEqual(pushes[0].batch_id, pushes[1].batch_id, 'тот же batch_id');
  assert.strictEqual(pushes[0].changes.operation[0].uuid, pushes[1].changes.operation[0].uuid, 'тот же uuid');
  await page.close();
});

test('повторный device_required — «Перезайдите…», без третьего запроса', async (t) => {
  if (skipReason) return t.skip(skipReason);
  const page = await ctx.context.newPage();
  let pushes = 0;
  await page.route('**/sync/push', (route) => {
    pushes++;
    return route.fulfill({ status: 403, json: { error: 'device_required' } });
  });
  await openManualCard(page);
  await page.locator('#ai-save-btn').click();
  await page.getByText('Перезайдите, чтобы записывать траты из браузера').waitFor({ timeout: 15000 });
  assert.strictEqual(pushes, 2);
  await page.close();
});

test('запись на живом контуре: расход доходит до отчёта операций', async (t) => {
  if (skipReason) return t.skip(skipReason);
  const page = await ctx.context.newPage();
  await openManualCard(page);
  await page.locator('#ai-save-btn').click();
  await page.getByText(/Записано:/).waitFor({ timeout: 15000 });
  // Период «Списка операций» по умолчанию заканчивается прошлым месяцем, поэтому
  // сверяемся с API отчёта за явный период, а не с лентой на экране.
  const today = new Date().toISOString().slice(0, 10);
  const res = await ctx.context.request.get(
    '/api/reports/operations?from=' + today + 'T00:00:00&to=' + today + 'T23:59:59&eq_currency=USD&limit=1000');
  const ops = (await res.json()).operations || [];
  assert.ok(ops.some((o) => o.category_name === seed.expense.name || JSON.stringify(o).includes(seed.expense.name)),
    'в отчёте за сегодня есть расход «' + seed.expense.name + '»');
  await page.close();
});
