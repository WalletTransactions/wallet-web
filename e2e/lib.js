'use strict';
// Общие помощники e2e-тестов wallet-web (change add-manual-operation).
//
// Что тестируется: РАБОЧАЯ КОПИЯ site/, а не задеплоенный образ. start() поднимает
// локальный сервер: файлы — из ../site, а /auth, /api, /sync, /admin
// проксируются на живой контур (так же делит пути gateway), поэтому куки
// сессии остаются в одном origin. E2E_SITE=deployed — не поднимать сервер и
// ходить прямо на E2E_BASE_URL (проверка уже выкаченной версии).
//
// Каждый набор тестов заводит СВОЕГО пользователя: POST /auth/register со
// случайным email, затем вход по паролю. У пользователя собственный леджер,
// чужие данные тесты не видят и не меняют. Пароль нигде не сохраняется.
//
// Настройка — переменными окружения:
//   E2E_BASE_URL  адрес контура (по умолчанию test на этом же хосте, http://127.0.0.1:8091)
//   E2E_SITE      deployed — без локального сервера, прямо на E2E_BASE_URL
//   E2E_CHROME    путь к Chrome/Chromium (по умолчанию /usr/bin/google-chrome)

const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const https = require('node:https');
const path = require('node:path');
const { chromium } = require('playwright-core');

const API = (process.env.E2E_BASE_URL || 'http://127.0.0.1:8091').replace(/\/+$/, '');
const CHROME = process.env.E2E_CHROME || '/usr/bin/google-chrome';
const SITE_DIR = path.join(__dirname, '..', 'site');
const PROXY_PREFIXES = ['/auth/', '/api/', '/sync/', '/admin/'];
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.yaml': 'text/yaml; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
};

const VIEWPORTS = {
  desktop: { width: 1280, height: 900 },
  phone: { width: 375, height: 760 },
};

let server = null;
let baseUrl = API;

function uuid() {
  return crypto.randomUUID();
}

function proxy(req, res) {
  const target = new URL(API);
  const lib = target.protocol === 'https:' ? https : http;
  const upstream = lib.request(
    {
      hostname: target.hostname,
      port: target.port,
      path: req.url,
      method: req.method,
      headers: Object.assign({}, req.headers, { host: target.host }),
      rejectUnauthorized: false,
    },
    (up) => {
      res.writeHead(up.statusCode, up.headers);
      up.pipe(res);
    }
  );
  upstream.on('error', () => {
    res.writeHead(502);
    res.end('bad gateway');
  });
  req.pipe(upstream);
}

function serveStatic(req, res) {
  const pathname = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  let file = path.join(SITE_DIR, pathname);
  // Защита от выхода из site/ и SPA-фолбэк на index.html, как у nginx.
  if (!file.startsWith(SITE_DIR) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) {
    file = path.join(SITE_DIR, 'index.html');
  }
  res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-store' });
  fs.createReadStream(file).pipe(res);
}

function handler(req, res) {
  if (PROXY_PREFIXES.some((p) => req.url.startsWith(p))) return proxy(req, res);
  return serveStatic(req, res);
}

// Поднимает локальный сервер (или нет — E2E_SITE=deployed) и возвращает адрес.
async function start() {
  if (process.env.E2E_SITE === 'deployed') {
    baseUrl = API;
    return baseUrl;
  }
  server = http.createServer(handler);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  baseUrl = 'http://127.0.0.1:' + server.address().port;
  return baseUrl;
}

async function stop() {
  if (!server) return;
  if (server.closeAllConnections) server.closeAllConnections();
  await new Promise((resolve) => server.close(resolve));
  server = null;
}

function launch() {
  return chromium.launch({ executablePath: CHROME, headless: true, args: ['--no-sandbox'] });
}

// Регистрация закрыта (REGISTRATION=closed) — тесты пропускаются, а не падают.
class RegistrationClosed extends Error {}

async function readJson(res) {
  try {
    return await res.json();
  } catch (e) {
    return {};
  }
}

// Новый контекст браузера с уже выполненным входом новым пользователем. Куки
// сессии лежат в контексте, поэтому страницы открываются сразу залогиненными.
async function newUserContext(browser, viewport) {
  const context = await browser.newContext({
    baseURL: baseUrl,
    viewport: viewport || VIEWPORTS.desktop,
    locale: 'ru-RU',
  });
  const methods = await readJson(await context.request.get('/auth/methods'));
  if (!methods.registration || (methods.methods || []).indexOf('password') < 0) {
    await context.close();
    throw new RegistrationClosed('на контуре закрыта регистрация или вход по паролю: ' + JSON.stringify(methods));
  }
  const user = {
    email: 'e2e+' + Date.now() + '-' + crypto.randomBytes(3).toString('hex') + '@example.test',
    password: crypto.randomBytes(12).toString('hex'),
  };
  const reg = await context.request.post('/auth/register', { data: { email: user.email, password: user.password } });
  if (reg.status() !== 202) throw new Error('register: HTTP ' + reg.status());
  const login = await context.request.post('/auth/login', { data: { email: user.email, password: user.password } });
  if (!login.ok()) throw new Error('login: HTTP ' + login.status());
  return { context, user };
}

// POST /sync/push от имени пользователя контекста. Возвращает {status, body}.
async function push(context, changes, batchId) {
  const res = await context.request.post('/sync/push', {
    data: { batch_id: batchId || uuid(), device_name: 'e2e', changes },
  });
  return { status: res.status(), body: await readJson(res) };
}

function accountRow(u, name, kind, categoryKind, iconUuid) {
  return {
    uuid: u,
    name,
    comment: '',
    icon_uuid: iconUuid,
    is_archived: false,
    system_kind: 0,
    kind, // 0 — категория, 1 — кошелёк
    category_kind: categoryKind, // 0 — расход, 1 — доход, 2 — оба
  };
}

// Засев леджера: кошелёк в валюте `iso` (по умолчанию USD), статья расхода
// «E2E Такси» и статья дохода «E2E Зарплата». Справочник валют и иконок общий
// и уже есть на контуре. Возвращает uuid и имена для проверок.
async function seedLedger(context, opts) {
  const iso = (opts && opts.iso) || 'USD';
  const res = await context.request.get('/api/reports/currencies');
  const currencies = (await readJson(res)).currencies || [];
  const cur = currencies.find((c) => c.iso_code === iso);
  if (!cur) throw new Error('в справочнике контура нет валюты ' + iso);

  const seed = {
    currency: cur,
    wallet: { uuid: uuid(), name: 'E2E Кошелёк' },
    expense: { uuid: uuid(), name: 'E2E Такси' },
    income: { uuid: uuid(), name: 'E2E Зарплата' },
  };
  const r = await push(context, {
    account: [
      accountRow(seed.wallet.uuid, seed.wallet.name, 1, 2, cur.icon_uuid),
      accountRow(seed.expense.uuid, seed.expense.name, 0, 0, cur.icon_uuid),
      accountRow(seed.income.uuid, seed.income.name, 0, 1, cur.icon_uuid),
    ],
    account_operating: [{ uuid: seed.wallet.uuid, currency_uuid: cur.uuid }],
  });
  if (r.status !== 200) throw new Error('seed push: HTTP ' + r.status + ' ' + JSON.stringify(r.body));
  return seed;
}

module.exports = {
  VIEWPORTS,
  uuid,
  start,
  stop,
  launch,
  newUserContext,
  push,
  seedLedger,
  RegistrationClosed,
};
