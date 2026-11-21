'use strict';
// Каркас: свежий пользователь входит по паролю и видит стартовый экран «Отчёты».

const { test, before, after } = require('node:test');
const assert = require('node:assert');
const lib = require('../lib');

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

test('новый пользователь по паролю попадает на «Отчёты»', async (t) => {
  if (skipReason) return t.skip(skipReason);
  const page = await ctx.context.newPage();
  await page.goto('/');
  await page.waitForSelector('#reports-title', { timeout: 15000 });
  assert.ok(await page.locator('.nav-item[data-view="ops"]').isVisible(), 'в сайдбаре есть «Список операций»');
});

test('тестируется рабочая копия site/, а не задеплоенный образ', async (t) => {
  if (skipReason) return t.skip(skipReason);
  if (process.env.E2E_SITE === 'deployed') return t.skip('E2E_SITE=deployed');
  const fs = require('node:fs');
  const path = require('node:path');
  const local = fs.readFileSync(path.join(__dirname, '..', '..', 'site', 'app.js'), 'utf8');
  const served = await (await ctx.context.request.get('/app.js')).text();
  assert.strictEqual(served, local);
});

test('засев кошелька и статей виден в справочнике', async (t) => {
  if (skipReason) return t.skip(skipReason);
  const seed = await lib.seedLedger(ctx.context);
  const res = await ctx.context.request.get('/api/reports/accounts');
  const names = (await res.json()).accounts.map((a) => a.name);
  for (const n of [seed.wallet.name, seed.expense.name, seed.income.name]) assert.ok(names.includes(n), n);
});
