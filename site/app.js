// SPA-логика wallet-web. Без фреймворков/сборки — тот же стиль, что раньше
// был в inline <script> у google-auth/wallet-bff (см. историю в README).
//
// Как узнаём, залогинены ли: cookie "session" — httpOnly, JS её прочитать
// НЕ МОЖЕТ (и не должен — именно ради защиты от XSS-кражи токена она такая).
// Поэтому вместо чтения cookie дёргаем GET /auth/me с credentials:'include'
// — браузер сам приложит cookie, сервер (google-auth) сам её проверит и
// отдаст 200+данные пользователя либо 401. Тот же приём для любого другого
// защищённого вызова (wallet-api).
(function () {
  'use strict';

  var app = document.getElementById('app');

  // Пользователь из последнего успешного GET /auth/me — нужен, чтобы кнопка
  // "Назад" на экране /admin/users могла вернуться в дашборд без лишнего
  // сетевого запроса (сам объект не меняется, пока не перелогинились).
  var currentUser = null;

  // "Посмотреть как клиент" (Role::Admin, кнопка в renderAdminTable) —
  // {id, email} пользователя, чей леджер сейчас показывают "Отчёты", или
  // null вне этого режима. Единственное место, которое его читает —
  // fetchReport() ниже (подмешивает as_user_id в КАЖДЫЙ запрос к
  // /api/reports/*, см. её комментарий и wallet-report/README.md,
  // "Посмотреть как клиент"); renderReports()/renderAdminTable() только
  // выставляют и показывают его, сами отчётные функции не меняются вовсе —
  // им всё равно, чей это леджер, они просто рисуют то, что пришло.
  var viewAsUser = null;

  // Токен из /join/<token> (org/docs/TODO_mobile_sync.md, Фаза 6, п. 9.4) —
  // должен пережить полный уход на google.com и обратно (Google-логин это
  // обычная навигация браузера, JS-состояние вкладки такой переход не
  // переживает), а google-auth после входа всегда возвращает на "/", не на
  // исходный /join/<token> (см. google.cpp, res.set_redirect("/")) — поэтому
  // localStorage, а не модульная переменная: он приходит и после полной
  // перезагрузки. try/catch — тот же приём, что у SIDEBAR_COLLAPSED_KEY
  // ниже (приватный режим/заблокированное хранилище не должны ронять вход).
  var PENDING_INVITE_TOKEN_KEY = 'pendingInviteToken';

  function getPendingInviteToken() {
    try {
      return localStorage.getItem(PENDING_INVITE_TOKEN_KEY);
    } catch (e) {
      return null;
    }
  }

  function setPendingInviteToken(token) {
    try {
      localStorage.setItem(PENDING_INVITE_TOKEN_KEY, token);
    } catch (e) {
      // приватный режим/заблокированное хранилище — приглашение придётся
      // принимать по ссылке ещё раз после логина, вход при этом не ломается
    }
  }

  function clearPendingInviteToken() {
    try {
      localStorage.removeItem(PENDING_INVITE_TOKEN_KEY);
    } catch (e) {
      // см. setPendingInviteToken выше
    }
  }

  // "/join/xxxxx" -> "xxxxx"; null — путь не похож на приглашение.
  function parseJoinPath(pathname) {
    var m = /^\/join\/([^/]+)\/?$/.exec(pathname || '');
    return m ? decodeURIComponent(m[1]) : null;
  }

  function escapeHtml(s) {
    var div = document.createElement('div');
    div.textContent = s;
    return div.innerHTML;
  }

  // escapeHtml не трогает кавычки — для значения атрибута в "…", куда идёт
  // текст, набранный пользователем (имя MCP-токена в data-name).
  function escapeAttr(s) {
    return escapeHtml(s).replace(/"/g, '&quot;');
  }

  // .card.wide — существовавший, но раньше нигде не применявшийся класс в
  // style.css (max-width 900px вместо обычных 460 — для таблиц). Экраны с
  // таблицей (список пользователей, отчёты) включают его, обычные узкие
  // экраны (логин, дашборд, ошибка) — выключают при заходе.
  function setWide(isWide) {
    // Сброс полноэкранного сайдбар-режима "Отчётов" (см. body.reports-open в
    // style.css) — вызывается ЛЮБЫМ другим экраном верхнего уровня
    // (renderLogin/renderError/renderSettings/renderAdminTable), поэтому
    // безопасно чистить его здесь один раз, а не в каждом из них отдельно.
    // Сам renderReports() эту функцию не вызывает — он выставляет
    // reports-open явно (см. её же комментарий).
    document.body.classList.remove('reports-open');
    app.classList.toggle('wide', isWide);
  }

  function roleBadgeHtml(role) {
    if (role === 'admin') return '<span class="badge admin">admin</span>';
    if (role === 'support') return '<span class="badge support">support</span>';
    return '<span class="badge user">user</span>';
  }

  // Access-токен живёт недолго (см. ACCESS_TOKEN_TTL_SECS на google-auth) —
  // если истёк, пока страница открыта, один раз тихо обновляем его через
  // /auth/refresh (по cookie refresh_token, Path=/auth) и повторяем запрос.
  function apiFetch(url, options) {
    return fetch(url, options).then(function (res) {
      if (res.status !== 401) return res;
      return fetch('/auth/refresh', { method: 'POST', credentials: 'include' }).then(
        function (refreshRes) {
          if (!refreshRes.ok) return res; // refresh тоже не удался — отдаём исходный 401
          return fetch(url, options);
        }
      );
    });
  }

  // Общая для renderLogin() и renderJoinLogin() (приглашение по ссылке,
  // см. "Доступ и приглашения" ниже) — сама кнопка одна и та же, разнится
  // только текст над ней.
  function googleLoginLinkHtml() {
    return (
      '<a class="google-btn" href="/auth/google">' +
      '<svg width="18" height="18" viewBox="0 0 48 48" aria-hidden="true">' +
      '<path fill="#FFC107" d="M43.6 20.5H42V20H24v8h11.3c-1.6 4.7-6.1 8-11.3 8-6.6 0-12-5.4-12-12s5.4-12 12-12c3.1 0 5.9 1.2 8 3.1l5.7-5.7C34.6 6.1 29.6 4 24 4 12.9 4 4 12.9 4 24s8.9 20 20 20 20-8.9 20-20c0-1.3-.1-2.7-.4-3.5z"/>' +
      '<path fill="#FF3D00" d="M6.3 14.7l6.6 4.8C14.6 15.9 18.9 13 24 13c3.1 0 5.9 1.2 8 3.1l5.7-5.7C34.6 6.1 29.6 4 24 4 16.3 4 9.7 8.3 6.3 14.7z"/>' +
      '<path fill="#4CAF50" d="M24 44c5.5 0 10.4-1.9 14.3-5.1l-6.6-5.6C29.6 35 26.9 36 24 36c-5.2 0-9.6-3.3-11.3-7.9l-6.6 5.1C9.6 39.6 16.3 44 24 44z"/>' +
      '<path fill="#1976D2" d="M43.6 20.5H42V20H24v8h11.3c-.8 2.3-2.3 4.3-4.2 5.7l6.6 5.6C41.5 36.4 44 30.6 44 24c0-1.3-.1-2.7-.4-3.5z"/>' +
      '</svg>' +
      'Войти через Google</a>'
    );
  }

  // message — необязательное сообщение НАД формой входа (сейчас только
  // "Аккаунт удалён." от wireDeleteAccount ниже, см. её комментарий) —
  // единственный экран, куда пользователь попадает уже без всякой сессии
  // сразу ПОСЛЕ своего же действия, поэтому именно здесь, а не window.alert
  // (тот потребовал бы отдельного клика "ОК" ровно тогда, когда действие
  // уже необратимо завершено).
  function renderLogin(message) {
    setWide(false);
    chatHide();
    app.innerHTML =
      '<h1>Кошельки</h1>' +
      (message ? '<p class="sub" style="color:var(--inc)">' + escapeHtml(message) + '</p>' : '') +
      '<p class="sub">Войдите через свою Google-учётную запись — сервер проверит ' +
      'подпись токена и вернёт вас сюда уже залогиненным.</p>' +
      googleLoginLinkHtml();
  }

  // Экран для /join/<token> (см. "Доступ и приглашения" ниже) — та же форма
  // входа, что renderLogin(), но с объясняющим текстом: пользователь мог
  // никогда раньше не открывать это приложение, ему нужен контекст, зачем
  // Google-логин вообще на пути. Сам токен уже отложен в localStorage к
  // моменту вызова (см. boot()) — эта функция только рисует, ничего не
  // сохраняет сама.
  function renderJoinLogin() {
    setWide(false);
    app.innerHTML =
      '<h1>Приглашение в кошелёк</h1>' +
      '<p class="sub">Вас пригласили в общий кошелёк. Войдите через свою Google-учётную ' +
      'запись — после входа приглашение примется само, и вы окажетесь внутри.</p>' +
      googleLoginLinkHtml();
  }

  function renderError(message) {
    setWide(false);
    app.innerHTML =
      '<h1>Что-то пошло не так</h1>' +
      '<p class="err">' + escapeHtml(message) + '</p>' +
      '<button type="button" class="btn" id="retry-btn">Обновить</button>';
    document.getElementById('retry-btn').addEventListener('click', boot);
  }

  // Кнопка, не ссылка — раньше это была навигация на server-rendered
  // /admin/users в google-auth (полная перезагрузка страницы, уход из SPA);
  // теперь это ещё один экран ЭТОЙ SPA (см. renderAdmin() ниже) — кнопка
  // на сайдбаре renderReports().
  function adminLinkButtonHtml(user) {
    return user.role === 'admin'
      ? '<button type="button" class="btn btn-secondary" id="admin-link-btn">Список пользователей</button>'
      : '';
  }

  // Аватарка+имя в углу сайдбара "Отчётов" (см. renderReports) — GET
  // /auth/me теперь отдаёт "picture" (URL Google-аватарки, "" если её нет —
  // см. AuthUser::picture в google-auth). Кружок с первой буквой имени —
  // и постоянный фолбэк на "нет аватарки", и то, что покажет onerror
  // <img> (см. wireAvatarFallback), если URL битый/недоступен.
  function userAvatarFallbackHtml(name) {
    var letter = (name || '').trim().charAt(0).toUpperCase() || '?';
    return '<div class="user-avatar-fallback">' + escapeHtml(letter) + '</div>';
  }

  function avatarHtml(user) {
    if (!user.picture) return userAvatarFallbackHtml(user.name);
    return '<img class="user-avatar" id="sidebar-avatar-img" src="' + escapeHtml(user.picture) + '" alt="">';
  }

  // Вызывать сразу после вставки avatarHtml() в DOM — если картинки не было
  // вовсе, id="sidebar-avatar-img" в разметке нет, getElementById просто
  // вернёт null (не ошибка).
  function wireAvatarFallback(user) {
    var img = document.getElementById('sidebar-avatar-img');
    if (!img) return;
    img.addEventListener('error', function () {
      img.outerHTML = userAvatarFallbackHtml(user.name);
    });
  }

  // Экран /admin/users (только Role::Admin, см. кнопку выше) — сшивает два
  // независимых источника по user_id/id:
  //  - GET /admin/users (google-auth) — email/роль/даты входа/сессии;
  //  - POST /api/reports/admin/users/stats (wallet-report) — кошельки/операции/
  //    даты операций/участники леджера, только по id из первого ответа.
  // Два отдельных сервиса, две отдельные базы (см. README wallet-report,
  // "Админ: агрегаты по пользователям...") — сшивание на клиенте вместо
  // похода одного сервиса в базу другого.
  //
  // Последовательно, а не параллельно: статистике нужны id из списка. Раньше
  // оба запроса шли разом, и wallet-report считал по ВСЕМ владельцам леджеров
  // базы — на стенде с данными нагрузочного теста 15,8 с и 1 МБ ради двух
  // строк. Список пользователей отвечает за миллисекунды, так что ожидание
  // на него дешевле.
  //
  // Строки статистики для какого-то id может не быть (пользователь ни разу
  // не синкал и ещё не владеет леджером) — statsByUserId.hasOwnProperty ниже
  // подставляет пустые счётчики, не роняя таблицу. Сбой статистики тоже не
  // роняет таблицу: email/роль важнее и без неё.
  function renderAdmin() {
    app.innerHTML = '<p class="sub">Загрузка…</p>';

    apiFetch('/admin/users', { credentials: 'include' })
      .then(function (res) {
        if (res.status === 401) { renderLogin(); return null; }
        return res.json().then(function (data) {
          if (!res.ok) throw new Error(data && data.error ? data.error : 'HTTP ' + res.status);
          return data;
        });
      })
      .then(function (usersData) {
        if (!usersData) return null; // 401 — renderLogin() уже вызван выше
        var ids = usersData.users.map(function (u) { return u.id; });
        var statsPromise = ids.length === 0 ? Promise.resolve({ users: [] }) :
          apiFetch('/api/reports/admin/users/stats', {
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ user_ids: ids }),
          })
            .then(function (res) { return res.ok ? res.json() : { users: [] }; })
            .catch(function () { return { users: [] }; });
        return statsPromise.then(function (statsData) { return [usersData, statsData]; });
      })
      .then(function (results) {
        if (!results) return;
        var statsByUserId = {};
        results[1].users.forEach(function (s) { statsByUserId[s.user_id] = s; });

        renderAdminTable(results[0].users.map(function (u) {
          var s = statsByUserId.hasOwnProperty(u.id) ? statsByUserId[u.id] : null;
          u.wallet_count = s ? s.wallet_count : '';
          u.operation_count = s ? s.operation_count : '';
          u.first_operation_date = s ? s.first_operation_date : '';
          u.last_operation_date = s ? s.last_operation_date : '';
          u.member_count = s ? s.member_count : '';
          return u;
        }));
      })
      .catch(function (err) {
        renderError('Не удалось загрузить список пользователей: ' + err.message);
      });
  }

  // "" -> "—" — и для пустых счётчиков (леджера ещё нет), и для timestamp'ов
  // без секунд/микросекунд не заботимся: показываем как прислал сервер,
  // только режем дальше первых 19 символов ("YYYY-MM-DD HH:MM:SS"), не
  // подсовывая пользователю миллисекунды/смещение таймзоны, которые здесь
  // не несут доп. смысла (те же поля — просто "когда" для человека, не
  // значение для расчётов).
  function adminCellText(value) {
    if (!value) return '—';
    return escapeHtml(String(value).slice(0, 19));
  }

  function adminCountText(value) {
    return value === '' || value === undefined ? '—' : escapeHtml(value);
  }

  // Колонки таблицы пользователей — одним списком: и заголовки, и подписи
  // ячеек на телефоне (data-label, см. style.css "Пользователи на телефоне"),
  // и пункты выбора сортировки. cls — роль ячейки в карточке на телефоне:
  // name/email — шапка карточки, minor — скрыта (второстепенное, есть на
  // десктопе), actions — кнопки внизу. sortable: false — колонка не
  // сортируется (кнопки). num — сортировать как числа, а не как текст
  // ("10" после "9", а не перед ним).
  var ADMIN_COLUMNS = [
    { label: 'Email', cls: 'cell-email', cell: function (u) { return escapeHtml(u.email); } },
    { label: 'Имя', cls: 'cell-name', cell: function (u) { return escapeHtml(u.name); } },
    { label: 'Роль', cell: function (u) { return roleBadgeHtml(u.role); } },
    { label: 'Email подтверждён', cls: 'cell-minor', cell: function (u) { return u.email_verified ? 'да' : 'нет'; } },
    { label: 'Регистрация', cls: 'cell-minor', cell: function (u) { return adminCellText(u.created_at); } },
    { label: 'Последний вход', cell: function (u) { return adminCellText(u.last_login_at); } },
    { label: 'Активных сессий', num: true, cell: function (u) { return String(u.active_sessions || 0); } },
    { label: 'Кошельков', num: true, cell: function (u) { return adminCountText(u.wallet_count); } },
    { label: 'Операций', num: true, cell: function (u) { return adminCountText(u.operation_count); } },
    { label: 'Первая операция', cls: 'cell-minor', cell: function (u) { return adminCellText(u.first_operation_date); } },
    { label: 'Последняя операция', cell: function (u) { return adminCellText(u.last_operation_date); } },
    { label: 'Участников леджера', cls: 'cell-minor', num: true, cell: function (u) { return adminCountText(u.member_count); } },
    { label: 'ID', cls: 'cell-minor', cell: function (u) { return '<code>' + escapeHtml(u.id) + '</code>'; } },
    { label: 'Действия', cls: 'cell-actions', sortable: false, cell: function (u) {
      return '<button type="button" class="btn-view-as" data-user-id="' + escapeHtml(u.id) +
        '" data-user-email="' + escapeHtml(u.email) + '">Посмотреть как клиент</button> ' +
        '<button type="button" class="btn-force-logout" data-user-id="' + escapeHtml(u.id) +
        '" data-user-email="' + escapeHtml(u.email) + '">Разлогинить</button>';
    } },
  ];

  function renderAdminTable(users) {
    setWide(true);
    var rows = users
      .map(function (u) {
        return '<tr>' + ADMIN_COLUMNS.map(function (col) {
          return '<td' + (col.cls ? ' class="' + col.cls + '"' : '') +
            ' data-label="' + escapeHtml(col.label) + '">' + col.cell(u) + '</td>';
        }).join('') + '</tr>';
      })
      .join('');

    var headers = ADMIN_COLUMNS.map(function (col) {
      return col.sortable === false ? '<th class="no-sort">' + col.label + '</th>' :
        '<th>' + col.label + '<span class="arrow"></span></th>';
    }).join('');

    // Сортировка на телефоне — выпадающим списком: заголовки там скрыты
    // (карточки вместо строк). Значение — "индекс колонки:направление".
    var sortOptions = '<option value="">Как пришло</option>';
    ADMIN_COLUMNS.forEach(function (col, i) {
      if (col.sortable === false || col.cls === 'cell-minor') return;
      sortOptions += '<option value="' + i + ':asc">' + col.label + ' ↑</option>' +
        '<option value="' + i + ':desc">' + col.label + ' ↓</option>';
    });

    app.innerHTML =
      '<h1>Пользователи</h1>' +
      '<p class="sub">Всего: ' + users.length + '. Клик по заголовку столбца сортирует таблицу.</p>' +
      '<label class="users-sort-mobile">Сортировать: <select id="users-sort">' + sortOptions + '</select></label>' +
      '<div class="users-table-wrap users-cards-wrap">' +
      '<table class="users" id="users-table">' +
      '<thead><tr>' + headers + '</tr></thead>' +
      '<tbody>' + rows + '</tbody>' +
      '</table>' +
      '</div>' +
      '<button type="button" class="btn btn-secondary" id="admin-icons-btn">Иконки</button> ' +
      '<button type="button" class="btn btn-secondary" id="admin-back-btn">Назад</button>';

    document.getElementById('admin-icons-btn').addEventListener('click', renderAdminIcons);
    document.getElementById('admin-back-btn').addEventListener('click', renderReports);

    wireAdminTableSorting();
    wireAdminForceLogout();
    wireAdminViewAs();
  }

  // "Посмотреть как клиент" — переключает viewAsUser (см. её объявление) и
  // открывает "Отчёты" под этим пользователем: renderReports() ничего не
  // знает про режим просмотра сам по себе, весь эффект — в fetchReport()
  // (подмешивает as_user_id) и в баннере viewAsBannerHtml() ниже.
  function wireAdminViewAs() {
    var table = document.getElementById('users-table');
    if (!table) return;

    table.tBodies[0].addEventListener('click', function (ev) {
      var btn = ev.target.closest ? ev.target.closest('.btn-view-as') : null;
      if (!btn) return;

      var id = btn.getAttribute('data-user-id');
      var email = btn.getAttribute('data-user-email');
      viewAsUser = { id: id, email: email };
      renderReports();
    });
  }

  // Сортировка кликом по заголовку (десктоп) или выбором в #users-sort
  // (телефон, заголовки скрыты) — один и тот же sortAdminTable.
  function wireAdminTableSorting() {
    var table = document.getElementById('users-table');
    if (!table) return;
    var headers = table.tHead.rows[0].cells;

    Array.prototype.forEach.call(headers, function (th, colIndex) {
      if (ADMIN_COLUMNS[colIndex].sortable === false) return;
      th.addEventListener('click', function () {
        sortAdminTable(table, colIndex, th.getAttribute('data-order') !== 'asc');
      });
    });

    var select = document.getElementById('users-sort');
    if (select) {
      select.addEventListener('change', function () {
        if (!select.value) return;
        var parts = select.value.split(':');
        sortAdminTable(table, Number(parts[0]), parts[1] === 'asc');
      });
    }
  }

  function sortAdminTable(table, colIndex, ascending) {
    var tbody = table.tBodies[0];
    var headers = table.tHead.rows[0].cells;
    var numeric = !!ADMIN_COLUMNS[colIndex].num;

    Array.prototype.forEach.call(headers, function (other) {
      other.removeAttribute('data-order');
      other.classList.remove('sorted');
      var arrow = other.querySelector('.arrow');
      if (arrow) arrow.textContent = '';
    });
    var th = headers[colIndex];
    th.setAttribute('data-order', ascending ? 'asc' : 'desc');
    th.classList.add('sorted');
    th.querySelector('.arrow').textContent = ascending ? '▲' : '▼';

    // Числа — числами: строкой "10" < "9". "—" (нет данных) — всегда в конце.
    function key(row) {
      var text = row.cells[colIndex].textContent.trim().toLowerCase();
      if (text === '—') return null;
      return numeric ? Number(text) : text;
    }
    var rows = Array.prototype.slice.call(tbody.rows);
    rows.sort(function (rowA, rowB) {
      var a = key(rowA), b = key(rowB);
      if (a === b) return 0;
      if (a === null) return 1;
      if (b === null) return -1;
      var cmp = a < b ? -1 : 1;
      return ascending ? cmp : -cmp;
    });
    rows.forEach(function (row) { tbody.appendChild(row); });
  }

  // Кнопка "Разлогинить" — POST /admin/users/:id/logout (см. admin.cpp),
  // отзывает и access-, и refresh-токен пользователя в Redis разом.
  // Мгновенно только для этого сервиса (см. README google-auth,
  // "Мгновенный logout — только в auth-сервисе") — wallet-api/wallet-gateway
  // про отзыв не узнают, их сессия жива до истечения exp.
  function wireAdminForceLogout() {
    var table = document.getElementById('users-table');
    if (!table) return;

    table.tBodies[0].addEventListener('click', function (ev) {
      var btn = ev.target.closest ? ev.target.closest('.btn-force-logout') : null;
      if (!btn) return;

      var id = btn.getAttribute('data-user-id');
      var email = btn.getAttribute('data-user-email');
      if (!window.confirm('Разлогинить ' + email + '? Текущие сессии (access и refresh) ' +
          'будут отозваны немедленно — в этом сервисе. wallet-api/wallet-gateway узнают ' +
          'об этом только когда access-токен истечёт сам.')) {
        return;
      }

      btn.disabled = true;
      apiFetch('/admin/users/' + encodeURIComponent(id) + '/logout', {
        method: 'POST',
        credentials: 'include',
      })
        .then(function (res) {
          if (res.status === 204) {
            btn.textContent = 'Разлогинен';
          } else {
            btn.disabled = false;
            window.alert('Не получилось (HTTP ' + res.status + ')');
          }
        })
        .catch(function () {
          btn.disabled = false;
          window.alert('Сетевая ошибка');
        });
    });
  }

  // "Иконки" (только Role::Admin, кнопка в renderAdminTable выше) — по
  // прямому запросу (2026-09-16): общий/эталонный набор иконок (виден всем
  // леджерам) сразу, плюс выбор пользователя из того же списка, что и
  // renderAdmin(), чтобы посмотреть его СОБСТВЕННЫЕ иконки (добавленные из
  // галереи в его леджер — см. wallet-api/schema/table/icon.sql, ledger_id NOT
  // NULL). GET /api/reports/admin/icons без user_id — только common.
  function renderAdminIcons() {
    app.innerHTML = '<p class="sub">Загрузка…</p>';

    Promise.all([
      apiJson('/api/reports/admin/icons', { credentials: 'include' }),
      apiJson('/admin/users', { credentials: 'include' }),
    ])
      .then(function (results) {
        var iconsData = results[0];
        var usersData = results[1];
        if (!iconsData || !usersData) return; // 401 — apiJson уже вызвал renderLogin()
        renderAdminIconsScreen(iconsData.common, usersData.users);
      })
      .catch(function (err) {
        renderError('Не удалось загрузить иконки: ' + err.message);
      });
  }

  // Иконки крупнее, чем в самих отчётах (.cat-icon, 26px) — здесь это не
  // подпись к операции среди текста, а единственное содержимое экрана,
  // "витрина" для просмотра/сверки, крупная картинка полезнее компактной.
  // opts.editable (только общий набор на админском экране, server-managed-icons)
  // — у ячейки data-uuid/data-name и кнопки «Переименовать»/«Удалить»;
  // обработчики — делегированием (wireAdminCommonIconsEvents). Иконки
  // пользователя и вкладка «Иконки» в «Отчётах» зовут без opts — только просмотр.
  function iconGridHtml(icons, opts) {
    if (icons.length === 0) return '<p class="wallet-empty">Иконок нет.</p>';
    var editable = !!(opts && opts.editable);
    return (
      '<div class="icon-admin-grid' + (editable ? ' editable' : '') + '">' +
      icons
        .map(function (i) {
          if (editable) return adminCommonIconCellHtml(i);
          return (
            '<div class="icon-admin-cell">' +
            categoryIconHtml(i.sha256, 'icon-admin-cat-icon') +
            '<div class="icon-admin-name">' + escapeHtml(i.name) + '</div>' +
            '</div>'
          );
        })
        .join('') +
      '</div>'
    );
  }

  // ---------- Общие иконки: запись (server-managed-icons) ----------
  // Набор ведёт администратор здесь; телефоны его только скачивают
  // (GET /sync/pull, поток справочников). Ручки — wallet-api,
  // /api/admin/icons* (тег admin-icons его openapi.yaml), байты картинки —
  // заранее через POST /sync/blobs. Просмотр (GET /api/reports/admin/icons)
  // — по-прежнему wallet-report.
  var ICON_SIZE = 256; // как хранит телефон (WEBP 256×256, BitmapFactory)
  var ICON_DUP_NAME = 'Общая иконка с таким названием уже есть.';

  // Состояние формы «Добавить иконку»: подготовленная картинка выбранного
  // файла. iconAddPrepared — Promise<Blob> (reject — не картинка),
  // iconAddPreviewUrl — objectURL превью (отзывается при смене/очистке).
  var iconAddPrepared = null;
  var iconAddPreviewUrl = null;

  function adminCommonIconCellHtml(i) {
    return (
      '<div class="icon-admin-cell" data-uuid="' + escapeAttr(i.uuid) + '" data-name="' + escapeAttr(i.name) + '">' +
      categoryIconHtml(i.sha256, 'icon-admin-cat-icon') +
      '<div class="icon-admin-name">' + escapeHtml(i.name) + '</div>' +
      '<div class="icon-admin-actions">' +
      '<button type="button" class="icon-admin-act" data-act="rename">Переименовать</button>' +
      '<button type="button" class="icon-admin-act danger" data-act="delete">Удалить</button>' +
      '</div>' +
      '<p class="icon-admin-err"></p>' +
      '</div>'
    );
  }

  function iconAddFormHtml() {
    return (
      '<form class="icon-add-form" id="icon-add-form" novalidate>' +
      '<h3>Добавить иконку</h3>' +
      '<div class="icon-add-row">' +
      '<div class="icon-add-preview" id="icon-add-preview"></div>' +
      '<label class="cur-field icon-add-file">Картинка<input type="file" id="icon-add-file" accept="image/*"></label>' +
      '<label class="cur-field">Название<input type="text" id="icon-add-name" maxlength="64" autocomplete="off"></label>' +
      '<label class="cur-field">Тип<select id="icon-add-type">' +
      '<option value="0">Категория</option><option value="1">Флаг</option>' +
      '</select></label>' +
      '<button type="submit" class="btn" id="icon-add-btn">Добавить</button>' +
      '</div>' +
      '<p class="err icon-add-err" id="icon-add-err"></p>' +
      '</form>'
    );
  }

  // Картинка → квадрат ICON_SIZE×ICON_SIZE: обрезка по центру, WEBP 0.9;
  // браузер без WEBP-кодировщика (Safari) отдаёт из toBlob PNG — берём
  // что вернулось. Наружу уходит только результат, не исходный файл.
  // objectURL, а не FileReader/dataURL: фото с телефона в 10+ МБ не
  // раздувается в base64-строку в памяти. reject — файл не декодируется.
  function prepareIconImage(file) {
    return new Promise(function (resolve, reject) {
      var url = URL.createObjectURL(file);
      var img = new Image();
      img.onload = function () {
        URL.revokeObjectURL(url);
        var w = img.naturalWidth, h = img.naturalHeight;
        var canvas = document.createElement('canvas');
        canvas.width = ICON_SIZE;
        canvas.height = ICON_SIZE;
        var ctx = canvas.getContext('2d');
        ctx.imageSmoothingEnabled = true;
        ctx.imageSmoothingQuality = 'high';
        try {
          if (w > 0 && h > 0) {
            var s = Math.min(w, h);
            ctx.drawImage(img, (w - s) / 2, (h - s) / 2, s, s, 0, 0, ICON_SIZE, ICON_SIZE);
          } else {
            ctx.drawImage(img, 0, 0, ICON_SIZE, ICON_SIZE); // SVG без собственного размера
          }
        } catch (e) {
          reject(e);
          return;
        }
        canvas.toBlob(function (blob) {
          if (blob) resolve(blob);
          else reject(new Error('canvas.toBlob'));
        }, 'image/webp', 0.9);
      };
      img.onerror = function () {
        URL.revokeObjectURL(url);
        reject(new Error('not an image'));
      };
      img.src = url;
    });
  }

  // Вызов wallet-api для формы/кнопок: 401 — экран входа (null), 204 — {},
  // иначе Error со status и телом (in_use у 409 удаления). Тело ошибки может
  // быть не JSON (HTML 502 от гейтвея) — тогда причина «HTTP <код>».
  function adminIconsApi(method, url, body, contentType) {
    var options = { method: method, credentials: 'include' };
    if (body !== undefined) {
      options.headers = { 'Content-Type': contentType || 'application/json' };
      options.body = contentType ? body : JSON.stringify(body);
    }
    return apiFetch(url, options).then(function (res) {
      if (res.status === 401) {
        renderLogin();
        return null;
      }
      if (res.status === 204) return {};
      return res.json().catch(function () { return null; }).then(function (data) {
        if (!res.ok) {
          var err = new Error(data && data.error ? data.error : 'HTTP ' + res.status);
          err.status = res.status;
          err.body = data || {};
          throw err;
        }
        return data || {};
      });
    });
  }

  // Перерисовка ТОЛЬКО раздела «Общие» (#admin-icons-common) — выбранный
  // пользователь в нижнем разделе и форма «Добавить иконку» не сбрасываются.
  // Старая сетка остаётся на экране, пока не придёт новая.
  function refreshAdminCommonIcons() {
    return apiJson('/api/reports/admin/icons', { credentials: 'include' })
      .then(function (data) {
        if (!data) return; // 401 — apiJson уже вызвал renderLogin()
        var el = document.getElementById('admin-icons-common');
        if (el) el.innerHTML = iconGridHtml(data.common, { editable: true });
      })
      .catch(function (err) {
        var el = document.getElementById('admin-icons-common');
        if (el) el.innerHTML = '<p class="err">Не удалось загрузить: ' + escapeHtml(err.message) + '</p>';
      });
  }

  function setIconAddPreview(blob) {
    var el = document.getElementById('icon-add-preview');
    if (iconAddPreviewUrl) URL.revokeObjectURL(iconAddPreviewUrl);
    iconAddPreviewUrl = blob ? URL.createObjectURL(blob) : null;
    if (el) el.style.backgroundImage = iconAddPreviewUrl ? 'url("' + iconAddPreviewUrl + '")' : '';
  }

  function wireIconAddForm() {
    var form = document.getElementById('icon-add-form');
    var fileInput = document.getElementById('icon-add-file');
    var nameInput = document.getElementById('icon-add-name');
    var typeSelect = document.getElementById('icon-add-type');
    var btn = document.getElementById('icon-add-btn');
    var errEl = document.getElementById('icon-add-err');
    iconAddPrepared = null;
    setIconAddPreview(null);

    fileInput.addEventListener('change', function () {
      var file = fileInput.files && fileInput.files[0];
      errEl.textContent = '';
      setIconAddPreview(null);
      if (!file) {
        iconAddPrepared = null;
        return;
      }
      var prepared = prepareIconImage(file);
      iconAddPrepared = prepared;
      prepared.then(
        function (blob) { if (iconAddPrepared === prepared) setIconAddPreview(blob); },
        function () { if (iconAddPrepared === prepared) errEl.textContent = 'Не удалось прочитать картинку.'; }
      );
    });

    form.addEventListener('submit', function (ev) {
      ev.preventDefault();
      if (btn.disabled) return;
      var name = nameInput.value.trim();
      var prepared = iconAddPrepared;
      if (!prepared || !name) {
        errEl.textContent = 'Выберите картинку и введите название.';
        return;
      }
      errEl.textContent = '';
      btn.disabled = true;
      btn.textContent = 'Добавление…';
      function done() {
        btn.disabled = false;
        btn.textContent = 'Добавить';
      }

      prepared
        .catch(function () {
          var e = new Error('Не удалось прочитать картинку.');
          e.local = true;
          throw e;
        })
        .then(function (blob) {
          return adminIconsApi('POST', '/sync/blobs', blob, 'application/octet-stream');
        })
        .then(function (blobData) {
          if (!blobData) return null; // 401
          return adminIconsApi('POST', '/api/admin/icons', {
            name: name,
            icon_type: Number(typeSelect.value),
            content_sha256: blobData.sha256,
          });
        })
        .then(function (created) {
          done();
          if (!created) return; // 401 — экран входа уже показан
          form.reset();
          iconAddPrepared = null;
          setIconAddPreview(null);
          return refreshAdminCommonIcons();
        })
        .catch(function (err) {
          done();
          if (err.local) errEl.textContent = err.message;
          else if (err.status === 409) errEl.textContent = ICON_DUP_NAME;
          else errEl.textContent = 'Не удалось: ' + err.message;
        });
    });
  }

  function adminIconCellError(cell, text) {
    var el = cell.querySelector('.icon-admin-err');
    if (el) el.textContent = text;
  }

  function startAdminIconRename(cell) {
    if (cell.classList.contains('editing')) return;
    cell.classList.add('editing');
    adminIconCellError(cell, '');
    var nameEl = cell.querySelector('.icon-admin-name');
    var actions = cell.querySelector('.icon-admin-actions');
    nameEl.innerHTML = '<input type="text" class="icon-admin-rename-input" maxlength="64" value="' +
      escapeAttr(cell.getAttribute('data-name')) + '">';
    actions.innerHTML =
      '<button type="button" class="icon-admin-act" data-act="save">Сохранить</button>' +
      '<button type="button" class="icon-admin-act" data-act="cancel">Отмена</button>';
    var input = nameEl.querySelector('input');
    input.focus();
    input.select();
  }

  function cancelAdminIconRename(cell) {
    cell.classList.remove('editing');
    adminIconCellError(cell, '');
    cell.querySelector('.icon-admin-name').textContent = cell.getAttribute('data-name');
    cell.querySelector('.icon-admin-actions').innerHTML =
      '<button type="button" class="icon-admin-act" data-act="rename">Переименовать</button>' +
      '<button type="button" class="icon-admin-act danger" data-act="delete">Удалить</button>';
  }

  function saveAdminIconRename(cell) {
    var input = cell.querySelector('.icon-admin-rename-input');
    var name = input.value.trim();
    if (name === cell.getAttribute('data-name')) {
      cancelAdminIconRename(cell);
      return;
    }
    var buttons = cell.querySelectorAll('.icon-admin-act');
    function setBusy(busy) {
      Array.prototype.forEach.call(buttons, function (b) { b.disabled = busy; });
    }
    adminIconCellError(cell, '');
    setBusy(true);
    adminIconsApi('PATCH', '/api/admin/icons/' + encodeURIComponent(cell.getAttribute('data-uuid')), { name: name })
      .then(function (data) {
        if (!data) return; // 401
        return refreshAdminCommonIcons();
      })
      .catch(function (err) {
        setBusy(false);
        adminIconCellError(cell, err.status === 409 ? ICON_DUP_NAME : 'Не удалось: ' + err.message);
        input.focus();
      });
  }

  function deleteAdminIcon(cell, btn) {
    var name = cell.getAttribute('data-name');
    if (!window.confirm('Удалить общую иконку «' + name + '»? Она пропадёт с телефонов при синхронизации.')) return;
    adminIconCellError(cell, '');
    btn.disabled = true;
    adminIconsApi('DELETE', '/api/admin/icons/' + encodeURIComponent(cell.getAttribute('data-uuid')))
      .then(function (data) {
        if (!data) return; // 401
        return refreshAdminCommonIcons();
      })
      .catch(function (err) {
        btn.disabled = false;
        if (err.status === 409) {
          var n = err.body && err.body.in_use != null ? ' (' + err.body.in_use + ')' : '';
          adminIconCellError(cell, 'Иконка используется' + n + ' — удалить нельзя.');
        } else {
          adminIconCellError(cell, 'Не удалось: ' + err.message);
        }
      });
  }

  // Один раз на контейнер #admin-icons-common: его содержимое
  // (refreshAdminCommonIcons) меняется, сам элемент — нет.
  function wireAdminCommonIconsEvents() {
    var root = document.getElementById('admin-icons-common');
    root.addEventListener('click', function (ev) {
      var btn = ev.target.closest ? ev.target.closest('.icon-admin-act') : null;
      if (!btn || btn.disabled) return;
      var cell = btn.closest('.icon-admin-cell');
      var act = btn.getAttribute('data-act');
      if (act === 'rename') startAdminIconRename(cell);
      else if (act === 'cancel') cancelAdminIconRename(cell);
      else if (act === 'save') saveAdminIconRename(cell);
      else if (act === 'delete') deleteAdminIcon(cell, btn);
    });
    root.addEventListener('keydown', function (ev) {
      if (!ev.target.classList || !ev.target.classList.contains('icon-admin-rename-input')) return;
      var cell = ev.target.closest('.icon-admin-cell');
      if (ev.key === 'Enter') {
        ev.preventDefault();
        var save = cell.querySelector('[data-act="save"]');
        if (save && !save.disabled) saveAdminIconRename(cell);
      } else if (ev.key === 'Escape') {
        cancelAdminIconRename(cell);
      }
    });
  }

  function renderAdminIconsScreen(commonIcons, users) {
    setWide(true);
    var userOptions = users
      .map(function (u) { return '<option value="' + escapeHtml(u.id) + '">' + escapeHtml(u.email) + '</option>'; })
      .join('');

    app.innerHTML =
      '<h1>Иконки</h1>' +
      '<p class="sub">Общий набор виден всем кошелькам и приезжает на телефоны при синхронизации. ' +
      'Выберите пользователя, чтобы посмотреть его собственные иконки (добавленные им самим ' +
      'из галереи, на сервер они не отправляются).</p>' +
      '<h2>Общие</h2>' +
      iconAddFormHtml() +
      '<div id="admin-icons-common">' + iconGridHtml(commonIcons, { editable: true }) + '</div>' +
      '<h2>Иконки пользователя</h2>' +
      '<div class="reports-controls">' +
      '<select id="admin-icons-user-select">' +
      '<option value="">— выбрать пользователя —</option>' +
      userOptions +
      '</select>' +
      '</div>' +
      '<div id="admin-icons-user-result"></div>' +
      '<button type="button" class="btn btn-secondary" id="admin-icons-back-btn">Назад</button>';

    document.getElementById('admin-icons-back-btn').addEventListener('click', renderAdmin);
    wireIconAddForm();
    wireAdminCommonIconsEvents();

    document.getElementById('admin-icons-user-select').addEventListener('change', function (ev) {
      var userId = ev.target.value;
      var resultEl = document.getElementById('admin-icons-user-result');
      if (!userId) {
        resultEl.innerHTML = '';
        return;
      }

      resultEl.innerHTML = '<p class="sub">Загрузка…</p>';
      apiJson('/api/reports/admin/icons?user_id=' + encodeURIComponent(userId), { credentials: 'include' })
        .then(function (data) {
          if (!data) return; // 401 — apiJson уже вызвал renderLogin()
          resultEl.innerHTML = iconGridHtml(data.user);
        })
        .catch(function (err) {
          resultEl.innerHTML = '<p class="err">Не удалось загрузить: ' + escapeHtml(err.message) + '</p>';
        });
    });
  }

  // "Иконки" в "Отчётах" (view 'icons', по прямому запросу, 2026-09-22) —
  // то же, что админская renderAdminIconsScreen выше, но про СВОЙ леджер:
  // GET /api/reports/icons (через fetchReport — значит, с as_user_id в
  // режиме "Посмотреть как клиент" и тем же кэшем "до кнопки Обновить").
  // Не зависит от периода/валюты — грузится один раз при открытии
  // "Отчётов", как "Курсы валют" и "Доступ" (см. конец renderReports()).
  function refreshIcons() {
    var root = document.getElementById('icons-root');
    fetchReport('icons', {})
      .then(function (data) {
        if (!data) return; // 401 — fetchReport уже вызвал renderLogin()
        root.innerHTML =
          '<h2>Мои (' + data.user.length + ')</h2>' +
          iconGridHtml(data.user) +
          '<h2>Общие (' + data.common.length + ')</h2>' +
          iconGridHtml(data.common);
      })
      .catch(function (err) {
        root.innerHTML = '<p class="err">Не удалось загрузить иконки: ' + escapeHtml(err.message) + '</p>';
      });
  }

  // "Устройства" (self-service, доступен всем, не только admin) —
  // GET/POST /auth/devices* (google-auth, см. его README, "Устройства").
  // В отличие от /admin/users (renderAdmin выше) — управляет только СВОИМИ
  // сессиями, не чужими. Мобильные сессии здесь уже не дублируются (сервер
  // схлопывает повторный вход того же device_id на самом выпуске токенов,
  // см. auth::issue_tokens) — эта страница ничего не группирует сама.
  //
  // Раньше был отдельным экраном верхнего уровня (свой back-button на
  // demo-CRUD "Кошельков") — переехал в "Настройки" (renderSettings ниже,
  // по прямому запросу 2026-09-11 — "Кошельки" убраны целиком). Рисует НЕ
  // в app.innerHTML, а в #settings-devices — секцию, которую уже вставила
  // renderSettings().
  function loadSettingsDevices() {
    apiFetch('/auth/devices', { credentials: 'include' })
      .then(function (res) {
        if (res.status === 401) {
          renderLogin();
          return null;
        }
        return res.json().then(function (data) {
          if (!res.ok) throw new Error(data && data.error ? data.error : 'HTTP ' + res.status);
          return data;
        });
      })
      .then(function (data) {
        if (!data) return;
        renderSettingsDevicesTable(data.devices);
      })
      .catch(function (err) {
        var container = document.getElementById('settings-devices-table');
        if (container) container.innerHTML = reportsErrorHtml('Не удалось загрузить список устройств: ' + err.message);
      });
  }

  // "Доступ и приглашения → Telegram-бот" (org/docs/TODO_telegram_bot.md,
  // шаг 7; была в "Настройках", перенесена 2026-09-29). Статус — связки
  // Telegram ↔ пользователь в google-auth: GET /auth/telegram/links,
  // отключение — DELETE /auth/telegram/links/{tg_user_id}
  // (org/docs/TODO_telegram_tokens.md, шаг 7). Сессией устройства бот больше
  // не является — в "Настройках → Устройства" его нет.
  //
  // Подключение: POST /auth/telegram/link-code (google-auth) → одноразовая
  // ссылка t.me/<бот>?start=<код> с TTL (по умолчанию 10 минут). Показываем
  // её кнопкой и QR-кодом (веб обычно на компьютере, Telegram — на
  // телефоне), затем опрашиваем связки, пока не появится НОВАЯ (пара
  // tg_user_id + created_at, которой не было в момент выдачи кода: повторное
  // подключение того же Telegram меняет created_at), или пока ссылка не
  // истечёт.
  var telegramLink = null; // {deepLink, expiresAt, knownKeys} — пока ссылка выдана и не использована
  var telegramPollTimer = null;
  var telegramJustLinked = false;

  function stopTelegramPoll() {
    if (telegramPollTimer) clearInterval(telegramPollTimer);
    telegramPollTimer = null;
  }

  function telegramLinkKey(l) {
    return l.tg_user_id + '|' + l.created_at;
  }

  function refreshTelegram() {
    var container = document.getElementById('telegram-root');
    if (!container) return;
    apiJson('/auth/telegram/links', { credentials: 'include' })
      .then(function (data) {
        if (data) renderTelegram(data.links || []);
      })
      .catch(function (err) {
        var c = document.getElementById('telegram-root');
        if (c) c.innerHTML = reportsErrorHtml('Не удалось узнать, подключён ли Telegram: ' + err.message);
      });
  }

  function renderTelegram(linked) {
    var container = document.getElementById('telegram-root');
    if (!container) return; // ушли с "Отчётов" (например, в "Настройки")

    var html = '';
    if (telegramJustLinked) {
      html += '<p class="telegram-ok">Готово — бот подключён. Напишите ему /help.</p>';
    }
    if (linked.length) {
      html += '<table class="users" id="telegram-table"><tbody>' +
        linked.map(function (l) {
          return '<tr><td>' + escapeHtml(l.name || 'Telegram') + '</td>' +
            '<td><span class="sub-id">с ' + escapeHtml(accessDate(l.created_at)) + '</span></td>' +
            '<td><button type="button" class="btn-force-logout" data-tg-user-id="' +
            escapeHtml(l.tg_user_id) + '">Отключить</button></td></tr>';
        }).join('') +
        '</tbody></table>' +
        '<button type="button" class="btn btn-secondary" id="telegram-link-btn">Подключить другой Telegram</button>';
    } else {
      html += '<p class="sub">Бот не подключён.</p>' +
        '<button type="button" class="btn" id="telegram-link-btn">Подключить Telegram</button>';
    }
    html += '<div id="telegram-link-box"></div>';
    container.innerHTML = html;

    document.getElementById('telegram-link-btn').addEventListener('click', function () {
      requestTelegramLink(linked);
    });
    var table = document.getElementById('telegram-table');
    if (table) table.addEventListener('click', onTelegramUnlinkClick);
    renderTelegramLinkBox();
  }

  function requestTelegramLink(linkedNow) {
    var btn = document.getElementById('telegram-link-btn');
    if (btn) btn.disabled = true;
    telegramJustLinked = false;
    apiFetch('/auth/telegram/link-code', { method: 'POST', credentials: 'include' })
      .then(function (res) {
        if (res.status === 401) {
          renderLogin();
          return null;
        }
        return res.json().then(function (data) {
          if (res.status === 503) throw new Error('бот на сервере ещё не настроен');
          if (!res.ok) throw new Error(data && data.error ? data.error : 'HTTP ' + res.status);
          return data;
        });
      })
      .then(function (data) {
        if (!data) return;
        telegramLink = {
          deepLink: data.deep_link,
          expiresAt: Date.now() + (data.expires_in || 600) * 1000,
          knownKeys: linkedNow.map(telegramLinkKey),
        };
        renderTelegramLinkBox();
        startTelegramPoll();
      })
      .catch(function (err) {
        var box = document.getElementById('telegram-link-box');
        if (box) box.innerHTML = reportsErrorHtml('Не удалось получить ссылку: ' + err.message);
      })
      .then(function () {
        var b = document.getElementById('telegram-link-btn');
        if (b) b.disabled = false;
      });
  }

  function telegramQrSvg(text) {
    if (typeof window.qrcode !== 'function') return ''; // библиотека не загрузилась — остаётся ссылка
    var qr = window.qrcode(0, 'M'); // 0 — размер по длине текста
    qr.addData(text);
    qr.make();
    return qr.createSvgTag({ cellSize: 4, margin: 16, scalable: true, alt: 'QR-код ссылки подключения' });
  }

  function renderTelegramLinkBox() {
    var box = document.getElementById('telegram-link-box');
    if (!box) return;
    if (!telegramLink) {
      box.innerHTML = '';
      return;
    }
    if (Date.now() >= telegramLink.expiresAt) {
      telegramLink = null;
      stopTelegramPoll();
      box.innerHTML = '<p class="sub">Ссылка истекла — нажмите «Подключить», чтобы получить новую.</p>';
      return;
    }
    var until = new Date(telegramLink.expiresAt);
    var hh = String(until.getHours()).padStart(2, '0');
    var mm = String(until.getMinutes()).padStart(2, '0');
    box.innerHTML =
      '<div class="telegram-link">' +
      '<div class="telegram-qr">' + telegramQrSvg(telegramLink.deepLink) + '</div>' +
      '<div class="telegram-link-text">' +
      '<p>Отсканируйте QR-код камерой телефона или откройте ссылку там, где установлен Telegram, ' +
      'и нажмите в боте «Запустить» (Start).</p>' +
      '<p><a class="btn" href="' + escapeHtml(telegramLink.deepLink) + '" target="_blank" rel="noopener">' +
      'Открыть в Telegram</a></p>' +
      '<p class="sub">Ссылка одноразовая, действует до ' + hh + ':' + mm + '. Не пересылайте её: ' +
      'кто откроет её первым, тот и получит доступ к вашему кошельку через бота.</p>' +
      '<p class="sub">Ждём подключения…</p>' +
      '</div></div>';
    // Вернулись в "Настройки" с ещё живой ссылкой — опрос к этому моменту
    // уже остановился сам (контейнера не было), запускаем снова.
    if (!telegramPollTimer) startTelegramPoll();
  }

  function startTelegramPoll() {
    stopTelegramPoll();
    telegramPollTimer = setInterval(function () {
      if (!document.getElementById('telegram-root') || !telegramLink) {
        stopTelegramPoll(); // ушли с "Отчётов" или ссылка уже неактуальна
        return;
      }
      if (Date.now() >= telegramLink.expiresAt) {
        renderTelegramLinkBox(); // покажет "истекла" и остановит опрос
        return;
      }
      apiFetch('/auth/telegram/links', { credentials: 'include' })
        .then(function (res) { return res.ok ? res.json() : null; })
        .then(function (data) {
          if (!data || !telegramLink) return;
          var known = telegramLink.knownKeys;
          var links = data.links || [];
          var fresh = links.some(function (l) { return known.indexOf(telegramLinkKey(l)) < 0; });
          if (!fresh) return;
          telegramLink = null;
          telegramJustLinked = true;
          stopTelegramPoll();
          renderTelegram(links);
        })
        .catch(function () { /* сеть мигнула — следующий тик попробует снова */ });
    }, 3000);
  }

  // "Отключить" — удаление связки в google-auth: бот больше не получит
  // токенов для этого пользователя (уже выданный живёт ≤ 5 минут) и на
  // следующей команде попросит подключиться заново.
  function onTelegramUnlinkClick(ev) {
    var btn = ev.target.closest ? ev.target.closest('.btn-force-logout') : null;
    if (!btn) return;
    if (!window.confirm('Отключить Telegram-бота? Он перестанет видеть ваш кошелёк и записывать траты.')) {
      return;
    }
    btn.disabled = true;
    telegramJustLinked = false;
    apiFetch('/auth/telegram/links/' + encodeURIComponent(btn.getAttribute('data-tg-user-id')), {
      method: 'DELETE',
      credentials: 'include',
    })
      .then(function (res) {
        if (res.status === 401) {
          renderLogin();
          return;
        }
        if (res.status === 204) {
          refreshTelegram();
          return;
        }
        return res.json().then(function (data) {
          throw new Error(data && data.error ? data.error : 'HTTP ' + res.status);
        });
      })
      .catch(function (err) {
        btn.disabled = false;
        window.alert('Не удалось отключить: ' + err.message);
      });
  }

  // MCP-токены (google-auth add-mcp-personal-tokens) — те же сессии
  // устройств, platform "mcp", device_name — имя токена. last_used_at/
  // expires_at google-auth отдаёт для всех сессий (null — неизвестно), здесь
  // они под меткой в "Статусе", в местном поясе (formatLocalDateTime).
  function deviceRowHtml(d) {
    var name = d.device_name ? escapeHtml(d.device_name) : (d.platform ? '(без имени)' : 'Браузер');
    var platform = d.platform === 'mcp' ? 'MCP-клиент' : (d.platform ? escapeHtml(d.platform) : '—');
    var status = d.is_current ? '<span class="badge ok">Текущее</span>' : '';
    if (d.last_used_at) {
      status += '<div class="device-when">Использовался ' + escapeHtml(formatLocalDateTime(d.last_used_at, true)) + '</div>';
    }
    if (d.expires_at) {
      status += '<div class="device-when">Действует до ' + escapeHtml(formatLocalDateTime(d.expires_at, false)) + '</div>';
    }
    var action = d.is_current
      ? '<span class="sub-id">выйдите через «Выйти»</span>'
      : '<button type="button" class="btn-force-logout" data-token-hash="' +
        escapeHtml(d.token_hash) + '" data-platform="' + escapeHtml(d.platform || '') +
        '" data-name="' + escapeAttr(d.device_name || '') + '">Отозвать</button>';
    return (
      '<tr' + (d.is_current ? ' class="device-current"' : '') + '>' +
      '<td>' + name + '</td>' +
      '<td>' + platform + '</td>' +
      '<td>' + status + '</td>' +
      '<td>' + action + '</td>' +
      '</tr>'
    );
  }

  // Рисует в #settings-devices-table, не в #settings-devices целиком: рядом
  // живёт #mcp-token-box (форма/показ MCP-токена), и перечитывание списка
  // (после отзыва, после «Готово») не должно стирать открытую форму.
  function renderSettingsDevicesTable(deviceList) {
    var container = document.getElementById('settings-devices-table');
    if (!container) return; // ушли с "Настроек" раньше, чем пришёл ответ
    var rows = deviceList.map(deviceRowHtml).join('');
    var othersCount = deviceList.filter(function (d) { return !d.is_current; }).length;

    container.innerHTML =
      (othersCount > 0
        ? '<button type="button" class="btn btn-secondary" id="devices-revoke-others-btn">' +
          'Закрыть все, кроме текущей (' + othersCount + ')</button>'
        : '') +
      '<div class="users-table-wrap">' +
      '<table class="users" id="devices-table">' +
      '<thead><tr><th>Устройство</th><th>Платформа</th><th>Статус</th><th>Действия</th></tr></thead>' +
      '<tbody>' + rows + '</tbody>' +
      '</table>' +
      '</div>';

    if (othersCount > 0) {
      document.getElementById('devices-revoke-others-btn').addEventListener('click', wireRevokeOthers);
    }
    wireRevokeOneDevice();
  }

  // Кнопка "Отозвать" в строке — POST /auth/devices/revoke {token_hash}.
  // Текущая сессия не несёт эту кнопку вообще (см. deviceRowHtml), поэтому
  // здесь не нужно отдельно её исключать.
  function wireRevokeOneDevice() {
    var table = document.getElementById('devices-table');
    if (!table) return;

    table.tBodies[0].addEventListener('click', function (ev) {
      var btn = ev.target.closest ? ev.target.closest('.btn-force-logout') : null;
      if (!btn) return;
      var tokenHash = btn.getAttribute('data-token-hash');

      // MCP: "5 минут" — срок JWT обмена (exp = 300 с, google-auth
      // add-mcp-personal-tokens), который wallet-mcp кеширует до exp.
      var question = btn.getAttribute('data-platform') === 'mcp'
        ? 'Отозвать MCP-токен «' + (btn.getAttribute('data-name') || '(без имени)') + '»? ' +
          'Клиент потеряет доступ к кошельку в течение 5 минут.'
        : 'Отозвать эту сессию? Устройство перестанет продлевать вход ' +
          'на нём, а его текущий доступ к этому сайту прервётся сразу — но доступ к ' +
          'кошелькам/отчётам ещё до 15 минут (см. README google-auth).';
      if (!window.confirm(question)) {
        return;
      }

      btn.disabled = true;
      apiFetch('/auth/devices/revoke', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token_hash: tokenHash }),
      })
        .then(function (res) {
          if (res.status === 401) {
            renderLogin();
            return;
          }
          if (res.status === 204) {
            loadSettingsDevices(); // перечитать список — эта строка исчезнет
            return;
          }
          return res.json().then(function (data) {
            throw new Error(data && data.error ? data.error : 'HTTP ' + res.status);
          });
        })
        .catch(function (err) {
          btn.disabled = false;
          window.alert('Не удалось отозвать: ' + err.message);
        });
    });
  }

  // Кнопка "Закрыть все, кроме текущей" — POST /auth/devices/revoke-others.
  function wireRevokeOthers() {
    var btn = document.getElementById('devices-revoke-others-btn');
    if (!window.confirm('Закрыть все остальные сессии? Все устройства, кроме этого, ' +
        'перестанут продлевать вход, а MCP-клиенты (например, LM Studio) потеряют ' +
        'доступ к кошельку.')) {
      return;
    }

    btn.disabled = true;
    apiFetch('/auth/devices/revoke-others', { method: 'POST', credentials: 'include' })
      .then(function (res) {
        if (res.status === 401) {
          renderLogin();
          return null;
        }
        return res.json().then(function (data) {
          if (!res.ok) throw new Error(data && data.error ? data.error : 'HTTP ' + res.status);
          return data;
        });
      })
      .then(function (data) {
        if (!data) return;
        loadSettingsDevices(); // перечитать — остальные строки исчезнут
      })
      .catch(function (err) {
        btn.disabled = false;
        window.alert('Не удалось закрыть остальные сессии: ' + err.message);
      });
  }

  // "Подключить MCP-клиент" (add-mcp-tokens-ui) — POST /auth/mcp-tokens
  // (google-auth add-mcp-personal-tokens, см. его openapi.yaml). Блок в
  // потоке #mcp-token-box в начале #settings-devices, по образцу
  // telegram-link-box, без модалки. Режим — null (кнопка) / 'form' / 'shown'.
  //
  // Сам токен НЕ хранится в переменных замыкания: он приходит в ответе,
  // сразу уходит в два <textarea readonly> и больше нигде не живёт — ни в
  // localStorage/sessionStorage, ни в адресе, ни в console. «Готово» или уход
  // с "Настроек" (renderSettings/любой другой экран перерисовывают app) —
  // и DOM с токеном исчезает, показать его снова нельзя.
  var mcpBoxMode = null;
  var mcpIssueSeq = 0; // ответ на выпуск, пришедший после ухода/повторного входа, не рисуется

  function mcpConfigText(token) {
    // Формат mcp.json LM Studio (https://lmstudio.ai/docs/app/mcp): удалённый
    // сервер — url + headers. Адрес — этот же контур (location.origin), / в
    // конце обязателен: гейтвей проксирует /api/mcp/.
    return JSON.stringify({
      mcpServers: {
        wallet: {
          url: location.origin + '/api/mcp/',
          headers: { Authorization: 'Bearer ' + token },
        },
      },
    }, null, 2);
  }

  function renderMcpTokenBox() {
    var box = document.getElementById('mcp-token-box');
    if (!box) return;
    if (mcpBoxMode === 'form') {
      box.innerHTML =
        '<div class="mcp-token-form">' +
        '<label class="mcp-field"><span>Название</span>' +
        '<input type="text" id="mcp-token-name" maxlength="64" placeholder="LM Studio дома" autocomplete="off"></label>' +
        '<p class="mcp-hint-err" id="mcp-token-name-err"></p>' +
        '<div class="mcp-token-buttons">' +
        '<button type="button" class="btn" id="mcp-token-issue-btn">Выпустить токен</button>' +
        '<button type="button" class="btn btn-secondary" id="mcp-token-cancel-btn">Отмена</button>' +
        '</div>' +
        '<p class="mcp-hint-err" id="mcp-token-error"></p>' +
        '</div>';
      var input = document.getElementById('mcp-token-name');
      input.focus();
      input.addEventListener('keydown', function (ev) {
        if (ev.key === 'Enter') issueMcpToken();
      });
      document.getElementById('mcp-token-issue-btn').addEventListener('click', issueMcpToken);
      document.getElementById('mcp-token-cancel-btn').addEventListener('click', function () {
        mcpBoxMode = null;
        mcpIssueSeq++;
        renderMcpTokenBox();
      });
      return;
    }
    // null; режим 'shown' рисует showMcpToken — здесь его не перерисовать: токена уже нет.
    mcpBoxMode = null;
    box.innerHTML = '<button type="button" class="btn btn-secondary mcp-connect-btn" id="mcp-connect-btn">' +
      'Подключить MCP-клиент</button>';
    document.getElementById('mcp-connect-btn').addEventListener('click', function () {
      mcpBoxMode = 'form';
      renderMcpTokenBox();
    });
  }

  function issueMcpToken() {
    var input = document.getElementById('mcp-token-name');
    var btn = document.getElementById('mcp-token-issue-btn');
    var nameErr = document.getElementById('mcp-token-name-err');
    var formErr = document.getElementById('mcp-token-error');
    if (!input || !btn || btn.disabled) return;
    var name = input.value.trim();
    nameErr.textContent = '';
    formErr.textContent = '';
    if (!name || name.length > 64) {
      nameErr.textContent = 'Введите название от 1 до 64 символов';
      return;
    }

    btn.disabled = true;
    var seq = ++mcpIssueSeq;
    apiFetch('/auth/mcp-tokens', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: name }),
    })
      .then(function (res) {
        if (seq !== mcpIssueSeq) return null;
        if (res.status === 401) {
          renderLogin();
          return null;
        }
        // Тело может быть не JSON (404 от nginx до выката google-auth) —
        // тогда причина "HTTP <код>".
        return res.json().catch(function () { return null; }).then(function (data) {
          if (res.status === 409) {
            var e409 = new Error('Слишком много MCP-токенов — отзовите ненужный в списке ниже.');
            e409.full = true;
            throw e409;
          }
          if (res.status !== 201 || !data || !data.token) {
            throw new Error(data && data.error ? data.error : 'HTTP ' + res.status);
          }
          return data;
        });
      })
      .then(function (data) {
        if (!data || seq !== mcpIssueSeq) return;
        showMcpToken(data);
      })
      .catch(function (err) {
        if (seq !== mcpIssueSeq) return;
        var e = document.getElementById('mcp-token-error');
        var b = document.getElementById('mcp-token-issue-btn');
        if (e) e.textContent = err.full ? err.message : 'Не удалось выпустить токен: ' + err.message;
        if (b) b.disabled = false; // название в поле не трогаем
      });
  }

  // data — ответ 201 {token, device_id, name, expires_at}; token отсюда
  // попадает только в value двух textarea.
  function showMcpToken(data) {
    var box = document.getElementById('mcp-token-box');
    if (!box) return;
    mcpBoxMode = 'shown';
    box.innerHTML =
      '<div class="mcp-token-shown">' +
      '<h3>Токен для «' + escapeHtml(data.name || '') + '»</h3>' +
      '<p class="mcp-token-warn">Скопируйте токен сейчас — больше он показан не будет. Отключится ' +
      escapeHtml(formatLocalDateTime(data.expires_at, false)) +
      ', если клиент не будет обращаться к кошельку; каждое обращение продлевает срок, но не дольше 90 дней с выпуска.</p>' +
      '<label class="mcp-field"><span>Токен</span>' +
      '<textarea readonly rows="2" class="mcp-token-value" id="mcp-token-value" spellcheck="false"></textarea></label>' +
      '<div class="mcp-copy-row">' +
      '<button type="button" class="btn btn-secondary" id="mcp-token-copy-btn">Скопировать токен</button>' +
      '<span class="mcp-copy-hint" id="mcp-token-copy-hint"></span></div>' +
      '<label class="mcp-field"><span>Конфиг MCP-клиента (mcp.json LM Studio)</span>' +
      '<textarea readonly rows="10" class="mcp-config-value" id="mcp-config-value" spellcheck="false"></textarea></label>' +
      '<div class="mcp-copy-row">' +
      '<button type="button" class="btn btn-secondary" id="mcp-config-copy-btn">Скопировать конфиг</button>' +
      '<span class="mcp-copy-hint" id="mcp-config-copy-hint"></span></div>' +
      '<div class="mcp-token-buttons">' +
      '<button type="button" class="btn" id="mcp-token-done-btn">Готово</button></div>' +
      '</div>';
    var tokenField = document.getElementById('mcp-token-value');
    var configField = document.getElementById('mcp-config-value');
    tokenField.value = data.token;
    configField.value = mcpConfigText(data.token);
    document.getElementById('mcp-token-copy-btn').addEventListener('click', function () {
      copyFieldText(tokenField, this, document.getElementById('mcp-token-copy-hint'));
    });
    document.getElementById('mcp-config-copy-btn').addEventListener('click', function () {
      copyFieldText(configField, this, document.getElementById('mcp-config-copy-hint'));
    });
    document.getElementById('mcp-token-done-btn').addEventListener('click', function () {
      mcpBoxMode = null;
      renderMcpTokenBox(); // стирает оба textarea вместе с токеном
      loadSettingsDevices(); // новая MCP-сессия появится в списке
    });
  }

  // Копирование секрета с честным фолбэком: в отличие от copyAccessLink,
  // без Clipboard API (стенд по http с IP — не secure context) или при
  // отказе записи НЕ притворяется, что скопировало, а выделяет текст поля и
  // просит нажать Ctrl+C — иначе блок закрыли бы с пустым буфером.
  function copyFieldText(field, btn, hint) {
    var label = btn.getAttribute('data-label') || btn.textContent;
    btn.setAttribute('data-label', label);
    if (hint) hint.textContent = '';
    var selectField = function () {
      field.focus();
      field.select();
      field.setSelectionRange(0, field.value.length); // iOS Safari не выделяет одним select()
      if (hint) hint.textContent = 'Выделено — нажмите Ctrl+C (⌘C на Mac)';
    };
    if (!navigator.clipboard || !navigator.clipboard.writeText) {
      selectField();
      return;
    }
    navigator.clipboard.writeText(field.value).then(function () {
      btn.textContent = 'Скопировано';
      setTimeout(function () { btn.textContent = label; }, 1500);
    }, selectField);
  }

  // "Настройки" — по прямому запросу (2026-09-11), заодно с удалением
  // demo-CRUD "Кошельков": единственная кнопка на сайдбаре "Отчётов" на
  // это место (settings-link-btn) взамен убранной "Кошельки". Две секции:
  // "Устройства" (см. loadSettingsDevices выше — перенесена сюда как есть,
  // без back-кнопки — вся страница теперь один экран) и валюта эквивалента.
  //
  // Валюта эквивалента — то же самое значение, что #eq-currency на
  // "Отчётах" (см. eqCurrencyValue/selectCurrency ниже), но с персистом в
  // localStorage: раньше "Отчёты" при каждом заходе молча откатывались на
  // "USD" (см. разметку renderReports) — теперь стартуют с последнего
  // выбора пользователя, а сам выбор можно поменять и отсюда, не только
  // пикером на "Отчётах" (тот тоже пишет в этот же ключ, см. selectCurrency).
  var EQ_CURRENCY_PREF_KEY = 'eqCurrencyPreference';

  function getEqCurrencyPreference() {
    try {
      return localStorage.getItem(EQ_CURRENCY_PREF_KEY);
    } catch (e) {
      return null; // приватный режим/заблокированное хранилище — просто нет сохранённого предпочтения
    }
  }

  function setEqCurrencyPreference(iso) {
    try {
      localStorage.setItem(EQ_CURRENCY_PREF_KEY, iso);
    } catch (e) {
      // см. getEqCurrencyPreference — предпочтение просто не переживёт эту вкладку
    }
  }

  // Формат отображения дат (по прямому запросу, дефолт дд.мм.гггг) — только
  // ГОТОВЫЙ текст дат, эхом идущих на экран как есть (курсы валют: последняя
  // дата в списке пар, история курса, подписи графика и хинт при наведении).
  // НЕ трогает: <input type="date"> (5 штук в приложении, см. #cur-rate-*/
  // #period-*) — тот их формат отображения задаёт браузер/ОС по value="yyyy-
  // mm-dd" из спеки HTML, JS/CSS отсюда его не переопределяет; и уже готовые
  // "человеческие" форматы других экранов (accessDate, opsDayLabel,
  // bucketAxisLabel и т.п. — "11 сентября 2026"/"Вчера") — те не сырой
  // YYYY-MM-DD текст, а собственный стиль под свой экран, менять их заодно
  // не просили.
  var DATE_FORMAT_PREF_KEY = 'dateFormatPreference';
  var DEFAULT_DATE_FORMAT = 'dmy';

  function getDateFormatPreference() {
    try {
      return localStorage.getItem(DATE_FORMAT_PREF_KEY) || DEFAULT_DATE_FORMAT;
    } catch (e) {
      return DEFAULT_DATE_FORMAT; // см. getEqCurrencyPreference — то же самое приватный режим/блокировка
    }
  }

  function setDateFormatPreference(fmt) {
    try {
      localStorage.setItem(DATE_FORMAT_PREF_KEY, fmt);
    } catch (e) {
      // см. setEqCurrencyPreference — предпочтение просто не переживёт эту вкладку
    }
  }

  // iso — "YYYY-MM-DD" или полный ISO-datetime (тогда время просто отбрасывается).
  function formatDate(iso) {
    if (!iso) return '';
    var d = iso.slice(0, 10);
    var y = d.slice(0, 4), m = d.slice(5, 7), day = d.slice(8, 10);
    switch (getDateFormatPreference()) {
      case 'ymd': return y + '-' + m + '-' + day;
      case 'mdy': return m + '/' + day + '/' + y;
      default: return day + '.' + m + '.' + y; // 'dmy' и любое незнакомое значение
    }
  }

  // Момент (ISO 8601 с поясом, обычно UTC) → дата в МЕСТНОМ поясе браузера в
  // формате из "Формата даты" и, при withTime, " ЧЧ:ММ". formatDate сам
  // отрезает первые 10 символов ISO-строки, т.е. берёт дату по UTC: для
  // 2026-10-31T22:30:00Z в UTC+3 вышло бы 31.10 вместо 01.11. Нужна для
  // моментов (сроки сессий, последнее использование), не для дат операций.
  function formatLocalDateTime(iso, withTime) {
    if (!iso) return '';
    var d = new Date(iso);
    if (isNaN(d.getTime())) return '';
    var p2 = function (n) { return (n < 10 ? '0' : '') + n; };
    var s = formatDate(d.getFullYear() + '-' + p2(d.getMonth() + 1) + '-' + p2(d.getDate()));
    return withTime ? s + ' ' + p2(d.getHours()) + ':' + p2(d.getMinutes()) : s;
  }

  // Пикер валюты в "Настройках" — по прямому запросу ("сделай такой же
  // красивый, как на Отчётах, с флагом") — тот же виджет currency-picker
  // (currencyRowHtml/categoryIconHtml, style.css), не select с <option>.
  // Отдельные функции от wireCurrencyPicker/selectCurrency на "Отчётах":
  // здесь нет #eq-currency и refreshPeriod() — только чтение/запись
  // eqCurrencyPreference в localStorage, тем же ключом (см. selectCurrency).
  function settingsCurrencyValue() {
    return getEqCurrencyPreference() || 'USD';
  }

  function renderSettingsCurrencyPickerList() {
    var listEl = document.getElementById('settings-currency-picker-list');
    if (!listEl) return;
    var current = settingsCurrencyValue();
    listEl.innerHTML = eqPickerCurrencies(current) // то же правило, что у пикера "Отчётов"
      .map(function (c) { return currencyRowHtml(c, c.iso_code === current); })
      .join('');
  }

  function renderSettingsCurrencyPickerButton() {
    var el = document.getElementById('settings-currency-picker-display');
    if (!el) return;
    var iso = settingsCurrencyValue();
    var c = currencyDirectory.filter(function (x) { return x.iso_code === iso; })[0];
    el.innerHTML =
      (c ? categoryIconHtml(c.icon_sha256, 'currency-picker-flag') : '<span class="currency-picker-flag"></span>') +
      '<span>' + escapeHtml(iso) + '</span>';
  }

  function closeSettingsCurrencyPickerList() {
    var listEl = document.getElementById('settings-currency-picker-list');
    if (listEl) listEl.hidden = true;
  }

  function selectSettingsCurrency(iso) {
    setEqCurrencyPreference(iso); // тот же ключ, что читает пикер на "Отчётах" (selectCurrency)
    renderSettingsCurrencyPickerButton();
    renderSettingsCurrencyPickerList();
    closeSettingsCurrencyPickerList();
  }

  function wireSettingsCurrencyPicker() {
    var btn = document.getElementById('settings-currency-picker-btn');
    var listEl = document.getElementById('settings-currency-picker-list');
    if (!btn || !listEl) return;
    btn.addEventListener('click', function (ev) {
      ev.stopPropagation();
      listEl.hidden = !listEl.hidden;
    });
    listEl.addEventListener('click', function (ev) {
      var row = ev.target.closest('.currency-picker-row');
      if (row) selectSettingsCurrency(row.getAttribute('data-iso'));
    });
    wireSettingsCurrencyPickerOutsideClick();
  }

  var settingsCurrencyPickerOutsideClickWired = false; // см. wireCurrencyPickerOutsideClick — тот же приём, свой на этот экран

  function wireSettingsCurrencyPickerOutsideClick() {
    if (settingsCurrencyPickerOutsideClickWired) return;
    settingsCurrencyPickerOutsideClickWired = true;
    document.addEventListener('click', function (ev) {
      var picker = document.getElementById('settings-currency-picker');
      var listEl = document.getElementById('settings-currency-picker-list');
      if (picker && listEl && !listEl.hidden && !picker.contains(ev.target)) listEl.hidden = true;
    });
  }

  // currencyDirectory могло ещё не подгрузиться (Settings открыли раньше,
  // чем ответил GET /api/reports/currencies, который зовёт renderReports() —
  // единственный путь туда) — тогда кнопка/список рендерятся с тем, что
  // есть (пустой список, флаг-заглушка), а этот download перерисует их,
  // когда (если) ответ придёт.
  function downloadSettingsCurrencyDirectory() {
    if (currencyDirectory.length) return; // уже пришёл (обычно — с "Отчётов", см. renderReports)
    fetchReport('currencies', {})
      .then(function (data) {
        if (!data || !data.currencies.length) return;
        currencyDirectory = data.currencies;
        currencySymbolByIso = {};
        data.currencies.forEach(function (c) { currencySymbolByIso[c.iso_code] = c.symbol; });
        renderSettingsCurrencyPickerList(); // ушли со страницы раньше — оба elementById вернут null внутри, не страшно
        renderSettingsCurrencyPickerButton();
      })
      .catch(function () {}); // тихо — тот же справочник ещё раз запросят "Отчёты"
  }

  function renderSettings() {
    setWide(true);
    var selectedIso = settingsCurrencyValue();
    mcpBoxMode = null; // показанный раньше MCP-токен при новом входе на экран не возвращается
    mcpIssueSeq++;

    app.innerHTML =
      '<h1>Настройки</h1>' +
      '<button type="button" class="btn btn-secondary" id="settings-back-btn">← Назад</button>' +
      '<section class="report-section">' +
      '<h2>Валюта эквивалента</h2>' +
      '<p class="sub">Валюта, в которой по умолчанию открываются «Отчёты» — запоминается в этом браузере.</p>' +
      '<label class="currency-picker" id="settings-currency-picker">' + // <label>, не <div> — тот же тег, что и у пикера на "Отчётах" (inline по умолчанию, иначе растянулся бы на всю ширину секции)
      '<button type="button" class="currency-picker-btn" id="settings-currency-picker-btn">' +
      '<span class="currency-picker-display" id="settings-currency-picker-display"><span class="currency-picker-flag"></span><span>' +
      escapeHtml(selectedIso) + '</span></span>' +
      '<svg class="currency-picker-arrow" viewBox="0 0 10 6" width="10" height="6" aria-hidden="true">' +
      '<path d="M1 1l4 4 4-4" fill="none" stroke="currentColor" stroke-width="1.5" ' +
      'stroke-linecap="round" stroke-linejoin="round"/></svg>' +
      '</button>' +
      '<div class="currency-picker-list" id="settings-currency-picker-list" hidden></div>' +
      '</label>' +
      '</section>' +
      '<section class="report-section">' +
      '<h2>Формат даты</h2>' +
      '<p class="sub">Как показывать даты в списках, таблицах и на графике курсов — запоминается в этом ' +
      'браузере. На поля выбора даты (календарь) не влияет — там формат всегда задаёт браузер.</p>' +
      '<label>Формат<select id="settings-date-format">' +
      '<option value="dmy">31.12.2026</option>' +
      '<option value="ymd">2026-12-31</option>' +
      '<option value="mdy">12/31/2026</option>' +
      '</select></label>' +
      '</section>' +
      '<section class="report-section">' +
      '<h2>Устройства</h2>' +
      '<p class="sub">Активные сессии вашего аккаунта — по одной на устройство. ' +
      'Отзыв снимает и refresh-, и парный access-токен немедленно — но только в ' +
      'этом сервисе: доступ к кошелькам/отчётам (wallet-api/wallet-gateway) ' +
      'сохранится до истечения access-токена (обычно 15 минут), см. README google-auth.</p>' +
      '<div id="settings-devices">' +
      '<div id="mcp-token-box"></div>' +
      '<div id="settings-devices-table"><p class="sub">Загрузка…</p></div>' +
      '</div>' +
      '</section>' +
      '<section class="danger-zone">' +
      '<h2>Опасная зона</h2>' +
      '<p class="sub">Удаляет ВСЕ ваши данные без возможности восстановления: кошельки, ' +
      'категории, операции, курсы — и саму учётную запись входа. Если у вас есть общий ' +
      'кошелёк с другими участниками, сначала передайте владение или удалите их на вкладке ' +
      '«Доступ и приглашения» — иначе удаление аккаунта будет отклонено.</p>' +
      '<button type="button" class="btn btn-danger" id="delete-account-btn">Удалить аккаунт</button>' +
      '</section>';

    document.getElementById('settings-back-btn').addEventListener('click', renderReports);
    renderSettingsCurrencyPickerButton();
    renderSettingsCurrencyPickerList();
    wireSettingsCurrencyPicker();

    var dateFormatSelect = document.getElementById('settings-date-format');
    dateFormatSelect.value = getDateFormatPreference();
    dateFormatSelect.addEventListener('change', function () {
      setDateFormatPreference(dateFormatSelect.value);
    });

    downloadSettingsCurrencyDirectory();
    renderMcpTokenBox();
    loadSettingsDevices();
    wireDeleteAccount();
  }

  // "Удалить аккаунт" (Опасная зона выше) — по прямому запросу: подтверждение,
  // при согласии удаление всей учётки из wallet-api И google-auth. Два
  // РАЗНЫХ сервиса, общей транзакции между ними нет и быть не может —
  // поэтому строго ПОСЛЕДОВАТЕЛЬНО, не Promise.all: сначала данные
  // (DELETE /api/account, wallet-api — через wallet-gateway), ПОТОМ сама
  // идентичность (DELETE /auth/me, google-auth). Если оборвётся ПОСЛЕ
  // первого шага — переживший пользователь БЕЗ данных, безопасно повторить
  // (оба удаления идемпотентны — см. их README/openapi.yaml); в обратном
  // порядке был бы риск идентичности БЕЗ данных, которой они принадлежат,
  // и уже ничей чужой мусор в wallet-api. См. openapi.yaml обоих сервисов,
  // "Удалить аккаунт".
  function wireDeleteAccount() {
    var btn = document.getElementById('delete-account-btn');
    if (!btn) return;

    btn.addEventListener('click', function () {
      if (!window.confirm(
          'Удалить аккаунт безвозвратно? Будут стёрты ВСЕ ваши кошельки, категории, ' +
          'операции и курсы, а также сама учётная запись входа. Отменить это нельзя.')) {
        return;
      }

      btn.disabled = true;
      apiJson('/api/account', { method: 'DELETE', credentials: 'include' })
        .then(function (data) {
          if (!data) return null; // 401 — apiJson уже показал renderLogin()
          // Второй шаг — только после успеха первого (см. комментарий выше).
          return apiJson('/auth/me', { method: 'DELETE', credentials: 'include' }).then(function (authData) {
            if (!authData) return; // 401 — сессия и так уже не пережила бы этот момент
            viewAsUser = null; // тот же приём, что logout-btn — не переживает выход
            currentUser = null;
            chatForget();
            renderLogin('Аккаунт удалён.');
          });
        })
        .catch(function (err) {
          btn.disabled = false;
          window.alert('Не удалось удалить аккаунт: ' + err.message);
        });
    });
  }

  // Экран "Отчёты" — GET /api/reports/balance|income|expense (wallet-api,
  // org/docs/TODO_mobile_sync.md, Фаза 4). Леджер на MVP один на пользователя
  // (см. план, п. 1.3) — переключателя леджера в UI поэтому нет, только
  // период/дата и валюта эквивалента.

  function firstDayOfMonthIso() {
    var d = new Date();
    d.setDate(1);
    return isoDate(d); // isoDate — function-декларация ниже по файлу, видна отовсюду; см. её комментарий про локальные компоненты вместо toISOString()
  }

  // Период "Обзора" по умолчанию — ПОСЛЕДНИЕ 12 ПОЛНЫХ календарных месяцев,
  // заканчивая предыдущим (по прямому запросу, 2026-09-11: "эти даты по
  // умолчанию год" — раньше, до этого, был всего один предыдущий месяц, см.
  // историю ниже). Не "с начала текущего месяца по сегодня" (было ДО ТОГО —
  // firstDayOfMonthIso() выше и today, см. isoDate(new Date()), тот же приём,
  // что и в opsDayLabel) — тот дефолт в первые дни нового месяца ужимался до
  // нескольких дней (например, 7 сентября — только 1..7 сентября) и почти
  // всегда показывал близкие к нулю суммы. Текущий (предыдущий) месяц НЕ
  // входит — весь год ВСЕГДА завершён, та же причина, что раньше была у
  // одного предыдущего месяца: график, последняя точка которого — "остаток
  // по состоянию на сегодня" вместо "на конец периода", как у остальных
  // точек, был бы кривой линией, а не улучшением. shiftMonth/lastDayOfMonth —
  // те же хелперы, что и у "Динамики" (объявлены ниже по файлу, но это
  // function-декларации, видны отовсюду в модуле).
  function defaultPeriodToIso() {
    return lastDayOfMonth(shiftMonth(firstDayOfMonthIso(), -1));
  }

  function defaultPeriodFromIso() {
    return shiftMonth(firstDayOfMonthIso(), -12);
  }

  // Персист дат фильтра (localStorage, по прямому запросу, 2026-09-11) — тот
  // же приём, что и eqCurrencyPreference у валюты эквивалента (см. ниже):
  // руками выбранный период переживает перезагрузку страницы, вместо того
  // чтобы каждый раз откатываться на дефолт (предыдущий календарный месяц,
  // см. defaultPeriodFromIso/-ToIso выше). Особый случай — дата РАВНА
  // "сегодня" в момент сохранения (по прямому запросу: "если это сегодня —
  // доп. признак, и на следующий день это опять сегодня"): хранится не сама
  // дата, а флаг "это было сегодня", иначе назавтра поле молча показывало бы
  // уже ВЧЕРАШНЕЕ число — при чтении флаг разворачивается в АКТУАЛЬНОЕ
  // "сегодня" на момент открытия страницы, а не в замороженную дату
  // сохранения. isoDate — определена ниже по файлу (function-декларация,
  // видна отовсюду в модуле), тот же UTC-приём "сегодня", что и everywhere
  // (см. firstDayOfMonthIso выше).
  var PERIOD_PREF_KEY = 'reportsPeriodPreference'; // {from, fromToday, to, toToday, groupBy}

  function getPeriodPreference() {
    try {
      var raw = localStorage.getItem(PERIOD_PREF_KEY);
      return raw ? JSON.parse(raw) : null;
    } catch (e) {
      return null; // приватный режим/заблокированное хранилище/битый JSON — просто нет сохранённого периода
    }
  }

  // groupByStr — период группировки графиков ("day"/"week"/"month", см.
  // #period-group/groupByValue ниже) — сохраняется в ТОМ ЖЕ объекте, что и
  // даты: это тоже часть фильтра, введённого руками, персистится тем же
  // приёмом (по прямому запросу, 2026-09-11, заодно с самими датами).
  function setPeriodPreference(fromStr, toStr, groupByStr) {
    try {
      var today = isoDate(new Date());
      localStorage.setItem(PERIOD_PREF_KEY, JSON.stringify({
        from: fromStr, fromToday: fromStr === today,
        to: toStr, toToday: toStr === today,
        groupBy: groupByStr,
      }));
    } catch (e) {
      // см. getPeriodPreference — предпочтение просто не переживёт эту вкладку
    }
  }

  // null, если предпочтения ещё нет вовсе — тогда в разметке renderReports в
  // ход идёт дефолт (defaultPeriodFromIso/-ToIso), как и раньше.
  function periodPreferenceFrom() {
    var p = getPeriodPreference();
    if (!p) return null;
    return p.fromToday ? isoDate(new Date()) : p.from;
  }

  function periodPreferenceTo() {
    var p = getPeriodPreference();
    if (!p) return null;
    return p.toToday ? isoDate(new Date()) : p.to;
  }

  function periodPreferenceGroupBy() {
    var p = getPeriodPreference();
    return (p && p.groupBy) || null;
  }

  // Тысячный разделитель для сумм в отчётах (по прямому запросу) — сервер
  // отдаёт "деньги как строку" (см. reports_repo.hpp, "деньги — numeric",
  // не double), поэтому группировка разрядов — чисто текстовая (regex по
  // строке), БЕЗ парсинга в Number: ни малейшего риска потерять точность на
  // большой сумме, само число как пришло, так и остаётся, только с
  // разделителями. Неразрывный пробел ( ), не обычный — группа тысяч
  // не должна сама расползтись переносом строки.
  // Тысячный разделитель для сумм в отчётах (по прямому запросу) — сервер
  // отдаёт "деньги как строку" (см. reports_repo.hpp, "деньги — numeric",
  // не double), поэтому группировка разрядов — чисто текстовая (regex по
  // строке), БЕЗ парсинга в Number: ни малейшего риска потерять точность на
  // большой сумме, само число как пришло, так и остаётся, только с
  // разделителями. Неразрывный пробел (U+00A0), не обычный — группа тысяч
  // не должна сама расползтись переносом строки.
  function groupThousands(numStr) {
    var neg = numStr.charAt(0) === '-' || numStr.charAt(0) === '−';
    var s = neg ? numStr.slice(1) : numStr;
    var dot = s.indexOf('.');
    var intPart = dot < 0 ? s : s.slice(0, dot);
    var fracPart = dot < 0 ? '' : s.slice(dot);
    intPart = intPart.replace(/\B(?=(\d{3})+(?!\d))/g, ' ');
    return (neg ? '−' : '') + intPart + fracPart;
  }

  // Знак валюты эквивалента — сервер /api/reports/* отдаёт только
  // eq_currency_uuid (внутренний id, см. reports_repo.hpp), не символ.
  // Раньше здесь была небольшая ЗАШИТАЯ таблица из десятка популярных ISO-
  // кодов (свободный текстовый ввод не позволял узнать символ иначе); теперь
  // #eq-currency — <select>, построенный из GET /api/reports/currencies (см.
  // loadCurrencies), и currencySymbolByIso — РЕАЛЬНЫЙ символ ИМЕННО ТЕХ
  // валют, что видны этому леджеру (включая локальные/крипто, которых в
  // зашитой таблице не могло быть по определению). Код, которого в
  // справочнике нет (список ещё не пришёл, либо сам код почему-то не
  // числится в нём), показывается как есть — ISO-код и сам по себе
  // достаточно однозначный "знак".
  var currencySymbolByIso = {}; // iso_code -> symbol, из loadCurrencies()

  function eqCurrencySymbol() {
    var iso = eqCurrencyValue();
    return currencySymbolByIso[iso] || iso;
  }

  // Сумма в валюте эквивалента, отформатированная для показа: разделитель
  // разрядов + знак валюты разом — единая точка для KPI/"Структуры"/
  // "Динамики"/итогов "Списка операций". Не показывает "~" сама (это разные
  // условия у разных вызывающих — total-level incomplete-флаг в одних
  // местах, пустая строка на КОНКРЕТНОЙ строке в других), просто форматирует
  // число, которое ей передали. escapeHtml на знаке — не паранойя: если
  // ISO-кода нет в currencySymbolByIso, eqCurrencySymbol() возвращает сам
  // текущий #eq-currency.value дословно (см. её комментарий выше).
  function fmtEq(numStr) {
    return groupThousands(numStr) + ' ' + escapeHtml(eqCurrencySymbol());
  }

  // Сумма в СВОЕЙ валюте операции (не в эквиваленте, см. fmtEq выше) — знак
  // приходит от сервера (OperationRow.symbol, "Список операций"), не из
  // ввода пользователя, но экранируем и его — то же правило "не доверяй
  // тексту в innerHTML", что и везде в этом файле.
  function fmtNative(numStr, symbol) {
    return groupThousands(numStr) + ' ' + escapeHtml(symbol);
  }

  function formatEqAmount(currencyUuid, eqCurrencyUuid, eqValue) {
    if (eqValue === '') return '<span class="eq-missing">~</span>';
    var formatted = fmtEq(eqValue);
    return currencyUuid === eqCurrencyUuid ? formatted : '≈ ' + formatted;
  }

  function reportsErrorHtml(message) {
    return '<p class="err">' + escapeHtml(message) + '</p>';
  }

  // Кэш ответов /api/reports/* — ключ - путь+query целиком (см. cacheKey
  // ниже), поэтому две ЛОГИЧЕСКИ одинаковые выборки (тот же период, та же
  // валюта, тот же режим сравнения — то есть в точности состояние, которое
  // captureReportsState() запомнил в reportsHistory ДО перехода "с
  // деталями") неотличимы и переиспользуют один и тот же ответ. Именно
  // поэтому "Назад" (goReportsBack) не требует отдельного кода для
  // "восстановить без похода в сеть" — он просто ставит старые значения
  // фильтра назад в поля и зовёт тот же refreshPeriod(), что и всегда: если
  // под эти значения уже что-то грузили (а при переходе "с деталями" —
  // всегда грузили, см. renderReports(), там всё разом), fetchReport()
  // отдаёт кэш, не сеть. Сбрасывается намеренно в двух местах: кнопка
  // "Обновить" (по прямому запросу — "перезапрос только по кнопке обновить,
  // и если нужные данные не были запрошены") и сам новый заход на "Отчёты"
  // (renderReports() — та же логика, что и у reportsHistory, см. там же).
  var reportsCache = {};

  // Запросы В ПОЛЁТЕ — по прямому запросу ("правь все пункты по нагрузке":
  // Обзор/Динамика/Категории во времени открываются ОДНИМ заходом на
  // "Отчёты" и КАЖДЫЙ сам заново запускает свою цепочку fetchReport, ещё до
  // того, как первый ответ вообще пришёл — reportsCache (кэш по РЕЗУЛЬТАТУ)
  // тут бессилен: на момент второго/третьего вызова кэш ещё пуст, запись в
  // него происходит только ПОСЛЕ ответа сети, а он к тому моменту уже давно
  // ушёл отдельным запросом. reportsInFlight ловит именно этот момент —
  // если запрос с ТЕМ ЖЕ path+query уже в полёте, второй (и третий) вызов
  // получает ТУ ЖЕ promise, а не плодит свой сетевой запрос. Особенно
  // ощутимо для /operations (см. fetchAllOperations) — если бы Обзор
  // запрашивал ТО ЖЕ окно, что и Динамика/Категории (см. refreshPeriod), вся
  // курсорная пагинация страница за страницей делилась бы между всеми
  // тремя, а не троилась.
  var reportsInFlight = {};

  function fetchReport(path, params) {
    // "Посмотреть как клиент" — единственная точка, где as_user_id
    // подмешивается в запрос (см. viewAsUser выше): копия params, не мутация
    // объекта вызывающего кода (он мог бы использовать его дальше, например
    // для собственного ключа кэша на своей стороне) — обычный цикл, не
    // Object.assign, тем же ES5-стилем, что и весь остальной файл.
    if (viewAsUser) {
      var paramsWithAsUser = {};
      for (var pk in params) if (params.hasOwnProperty(pk)) paramsWithAsUser[pk] = params[pk];
      paramsWithAsUser.as_user_id = viewAsUser.id;
      params = paramsWithAsUser;
    }
    var query = Object.keys(params)
      .map(function (k) { return encodeURIComponent(k) + '=' + encodeURIComponent(params[k]); })
      .join('&');
    var cacheKey = path + '?' + query;
    if (reportsCache.hasOwnProperty(cacheKey)) return Promise.resolve(reportsCache[cacheKey]);
    if (reportsInFlight.hasOwnProperty(cacheKey)) return reportsInFlight[cacheKey];

    var promise = apiFetch('/api/reports/' + path + '?' + query, { credentials: 'include' })
      .then(function (res) {
        if (res.status === 401) {
          renderLogin(); // refresh тоже не спас — сессия реально кончилась
          return null; // 401 — не кэшируем: это не данные, а сигнал "перелогинься"
        }
        // Тело ошибки может быть не JSON (404 гейтвея на неизвестный путь) —
        // тогда просто «HTTP <код>». status — в самой ошибке: «Капитал»
        // отличает 404 (wallet-report без ручки, capital-assets D7) от сбоя.
        var body = res.ok ? res.json() : res.json().catch(function () { return null; });
        return body.then(function (data) {
          if (!res.ok) {
            var err = new Error(data && data.error ? data.error : 'HTTP ' + res.status);
            err.status = res.status;
            throw err;
          }
          reportsCache[cacheKey] = data; // кэшируем ТОЛЬКО успешный ответ — ошибка не должна "залипать"
          return data;
        });
      })
      .finally(function () {
        // Снимается независимо от исхода — упавший запрос НЕ должен
        // навсегда "застрять" в reportsInFlight (следующий вызов с тем же
        // ключом обязан получить шанс попробовать заново, а не унаследовать
        // чужой отказ до конца жизни SPA).
        delete reportsInFlight[cacheKey];
      });
    reportsInFlight[cacheKey] = promise;
    return promise;
  }

  // /api/reports/operations теперь отдаёт курсорными страницами по 1000 (по
  // прямому запросу, 2026-09-12 — "если выбираем 20 лет, то нет
  // необходимости доставать всё"). "Обзору"/"Динамике"/"Категориям во
  // времени" для клиентской агрегации (sumIncomeExpenseByBucket,
  // buildCatsFromOperations) по-прежнему нужны ВСЕ операции окна целиком —
  // им курсор не нужен, они просто дособирают его сами, страница за
  // страницей, вместо одного гигантского запроса, каким был раньше один
  // fetchReport('operations', ...). Итоговая форма ({operations, incomplete})
  // — та же, что и раньше отдавал fetchReport('operations', ...) целиком
  // (has_more/next_cursor_* — только служебные поля отдельных страниц,
  // наружу отсюда не нужны), поэтому вызывающий код (refreshOverview/
  // refreshDynamics/refreshCategories) не меняется вовсе.
  //
  // "Список операций" (человек скроллит) эту функцию НЕ использует — там
  // настоящая ленивая подгрузка по доскроллу, см. wireOpsInfiniteScroll:
  // предзагружать всё окно целиком там как раз и значило бы наступить на
  // грабли, ради которых пагинация вообще заводилась.
  function fetchAllOperations(params) {
    var operations = [];
    var incomplete = false;

    function loadPage(cursorDate, cursorUuid) {
      var pageParams = { from: params.from, to: params.to, eq_currency: params.eq_currency, limit: 1000 };
      if (cursorDate) {
        pageParams.cursor_date = cursorDate;
        pageParams.cursor_uuid = cursorUuid;
      }
      return fetchReport('operations', pageParams).then(function (data) {
        if (!data) return null; // 401 — renderLogin() уже сработал внутри fetchReport
        operations = operations.concat(data.operations);
        if (data.incomplete) incomplete = true;
        if (data.has_more) return loadPage(data.next_cursor_date, data.next_cursor_uuid);
        return { operations: operations, incomplete: incomplete };
      });
    }

    return loadPage(null, null);
  }

  // Батчинг /api/reports/balance-at-dates (по прямому запросу, 2026-09-11) —
  // попытка чинить "Failed to fetch" на "Обзоре"/"Динамике" на клиенте, ДО
  // того как появилось /api/reports/balance-series (сервер сам строит
  // границы бакетов из from/to/step, см. reports.cpp::handle_balance_series)
  // — теперь оба экрана зовут balance-series напрямую, отдельного батчинга
  // не нужно. Сам /balance-at-dates остался — им по-прежнему пользуются
  // "Кошельки и остатки" (см. refreshWalletBalances), там всегда ≤14 дат,
  // ограничение URI недостижимо.

  // "Итого" помечается "~" (а не оставляется без числа, как у отдельной
  // строки) — сумма реальна, но занижена на неизвестную величину: то же
  // правило "в агрегатах ~ перекрывает ≈", что и в Android-приложении (см.
  // android-wallet/docs/ARCHITECTURE.md).
  function reportTotalHtml(data) {
    return (data.incomplete ? '~ ' : '') + fmtEq(data.total_eq);
  }

  function eqCurrencyValue() {
    return document.getElementById('eq-currency').value.trim().toUpperCase() || 'USD';
  }

  // Справочник валют — сами строки {uuid, iso_code, name, symbol,
  // icon_sha256} из GET /api/reports/currencies (loadCurrencies), нужен и
  // для построения списка (renderCurrencyPickerList), и для отображения
  // выбранной валюты в кнопке (renderCurrencyPickerButton) — оба места берут
  // отсюда, не ходят в сеть заново.
  var currencyDirectory = [];

  // Флаг/иконка валюты в выпадающем списке (по прямому запросу — "добавь
  // ещё и флаг страны") — ТА ЖЕ categoryIconHtml, что и у категорий: разница
  // только в имени класса-модификатора размера (currency-picker-flag/-row-flag,
  // style.css), сам механизм (background-image на /sync/blobs/:sha256)
  // общий, заводить копию под другое название незачем. currency.icon_uuid
  // NOT NULL (см. wallet-api/schema/table/currency.sql) — icon_sha256 пуст
  // только пока сам currencyDirectory ещё не загрузился.
  function currencyRowHtml(c, isActive) {
    return (
      '<div class="currency-picker-row' + (isActive ? ' active' : '') + '" data-iso="' +
      escapeHtml(c.iso_code) + '">' +
      categoryIconHtml(c.icon_sha256, 'currency-picker-row-flag') +
      '<span class="currency-picker-row-code">' + escapeHtml(c.iso_code) + '</span>' +
      '<span class="currency-picker-row-name">' + escapeHtml(c.name) + '</span>' +
      '</div>'
    );
  }

  // Валюты для пикеров эквивалента ("Отчёты", "Настройки") и автовыбора в
  // loadCurrencies (currency-ui-tweaks, design D1) — правило в одном месте:
  // только show_in_equivalent (нет поля — старый wallet-report — значит
  // true, D6) плюс текущая, даже если её скрыли (отчёты не перескакивают
  // молча в другую валюту); флаг снят у всех — весь справочник. Пикеры
  // формы "Добавить пару" флаг не учитывают (там справочник целиком).
  function eqPickerCurrencies(currentIso) {
    var anyShown = false;
    var list = currencyDirectory.filter(function (c) {
      var shown = c.show_in_equivalent !== false;
      if (shown) anyShown = true;
      return shown || c.iso_code === currentIso;
    });
    return anyShown ? list : currencyDirectory.slice();
  }

  function renderCurrencyPickerList() {
    var listEl = document.getElementById('currency-picker-list');
    if (!listEl) return;
    var current = eqCurrencyValue();
    listEl.innerHTML = eqPickerCurrencies(current)
      .map(function (c) { return currencyRowHtml(c, c.iso_code === current); })
      .join('');
  }

  // Кнопка-заглавие пикера — флаг + код текущей валюты (по прямому запросу);
  // вызывается и после загрузки справочника, и после goReportsBack()
  // (кнопка "Назад" меняет #eq-currency.value напрямую, без клика по
  // пикеру — саму кнопку тоже надо перерисовать, иначе она молча покажет
  // ПРЕЖНЮЮ валюту вместо восстановленной).
  function renderCurrencyPickerButton() {
    var el = document.getElementById('currency-picker-display');
    if (!el) return;
    var iso = eqCurrencyValue();
    var c = currencyDirectory.filter(function (x) { return x.iso_code === iso; })[0];
    el.innerHTML =
      (c ? categoryIconHtml(c.icon_sha256, 'currency-picker-flag') : '<span class="currency-picker-flag"></span>') +
      '<span>' + escapeHtml(iso) + '</span>';
  }

  function closeCurrencyPickerList() {
    var listEl = document.getElementById('currency-picker-list');
    if (listEl) listEl.hidden = true;
  }

  // Выбор валюты в пикере — по прямому запросу ("смена валюты эквивалента
  // так же обновляет данные") сразу зовёт refreshPeriod(), а не ждёт клика
  // по "Обновить" (та же логика, что и у смены "Сравнить с" в шапке).
  // Отдельно "инвалидировать кэши других страниц" не нужно: eq_currency —
  // часть query-строки КАЖДОГО запроса к /api/reports/* (см. cacheKey в
  // fetchReport), значит смена валюты сама по себе уже даёт другой ключ
  // кэша везде, где эта валюта участвует — включая вкладки, до которых
  // refreshPeriod() дойдёт не сразу (Структура/Динамика/Список
  // операций/Категории — она и их всех перезапрашивает, см. её код).
  function selectCurrency(iso) {
    document.getElementById('eq-currency').value = iso;
    setEqCurrencyPreference(iso); // тот же ключ, что читает "Настройки" — пикер здесь тоже меняет предпочтение
    renderCurrencyPickerButton();
    renderCurrencyPickerList(); // подсветка .active — при СЛЕДУЮЩЕМ открытии список должен показывать уже ЭТУ валюту, не прежнюю
    closeCurrencyPickerList();
    refreshPeriod();
  }

  // Открытие/закрытие списка — сама кнопка/список пересоздаются заново при
  // каждом renderReports() (обычная разметка внутри app.innerHTML), поэтому
  // слушатели на НИХ вешаются каждый раз без риска накопить копии — старые
  // умирают вместе со старыми узлами. "Клик мимо — закрыть" отдельно, см.
  // wireCurrencyPickerOutsideClick ниже: document переживает renderReports(),
  // ему нужен ОДИН слушатель на всё время жизни SPA, не новый на каждый заход.
  function wireCurrencyPicker() {
    var btn = document.getElementById('currency-picker-btn');
    var listEl = document.getElementById('currency-picker-list');
    if (!btn || !listEl) return;
    btn.addEventListener('click', function (ev) {
      ev.stopPropagation(); // иначе тут же сработал бы обработчик "клик мимо" ниже и сразу закрыл только что открытый список
      listEl.hidden = !listEl.hidden;
    });
    listEl.addEventListener('click', function (ev) {
      var row = ev.target.closest('.currency-picker-row');
      if (row) selectCurrency(row.getAttribute('data-iso'));
    });
    wireCurrencyPickerOutsideClick();
  }

  var currencyPickerOutsideClickWired = false; // см. wireCurrencyPickerOutsideClick

  function wireCurrencyPickerOutsideClick() {
    if (currencyPickerOutsideClickWired) return;
    currencyPickerOutsideClickWired = true;
    document.addEventListener('click', function (ev) {
      var picker = document.getElementById('currency-picker');
      var listEl = document.getElementById('currency-picker-list');
      // Оба ищутся заново по id, не через замыкание на узлы момента
      // подписки — к моменту клика "Отчёты" могли перестраиваться сколько
      // угодно раз (см. комментарий выше, почему это ОДИН слушатель на всю
      // жизнь SPA, а не новый на каждый renderReports()).
      if (picker && listEl && !listEl.hidden && !picker.contains(ev.target)) listEl.hidden = true;
    });
  }

  // Справочник валют эквивалента (GET /api/reports/currencies, по прямому
  // запросу — "валюта эквивалента справочником") — грузится при открытии
  // "Отчётов" (см. конец renderReports()) и по "Обновить" (wallet-web#12),
  // но не при каждом refreshPeriod(): список валют леджера не зависит от
  // периода/фильтров.
  // Пока ответ не пришёл, #eq-currency держит "USD" из разметки (см.
  // renderReports) — с ним отчёты открываются сразу, кнопка пикера при этом
  // показывает пустой флаг-заглушку (currencyDirectory ещё пуст).
  function loadCurrencies() {
    return fetchReport('currencies', {}) // promise — для reloadCurrencyDirectory ниже; renderReports его не ждёт
      .then(function (data) {
        // Пустой справочник (леджера нет вовсе и ни одной ОБЩЕЙ валюты в
        // схеме — см. README wallet-api) — не заменять список валют
        // буквально пустым, заглушка "USD" в кнопке так и останется висеть.
        if (!data || !data.currencies.length) return;
        currencyDirectory = data.currencies;
        currencySymbolByIso = {};
        data.currencies.forEach(function (c) { currencySymbolByIso[c.iso_code] = c.symbol; });

        var isoList = data.currencies.map(function (c) { return c.iso_code; });
        var current = eqCurrencyValue();
        renderCurrencyPickerList();
        renderCurrencyPickerButton();
        renderSettingsCurrencyPickerList(); // перезапрос после записи валюты (D3) — оба пикера; вне своего экрана — no-op
        renderSettingsCurrencyPickerButton();
        renderCurCurrencies(); // вкладка "Справочник валют" могла открыться раньше, чем пришёл справочник
        // Заглушка "USD" могла не совпасть ни с одной реальной валютой этого
        // леджера (у него может не быть USD вовсе) — тогда молча остались бы
        // висеть под несуществующей валютой. Вместо этого явно берём первую
        // валюту СПИСКА ПИКЕРА (справочник ORDER BY iso_code на сервере, см.
        // reports_repo.hpp, без скрытых из эквивалента — eqPickerCurrencies)
        // и перезапрашиваем период под неё — иначе KPI на "Обзоре"
        // продолжали бы грузиться под "USD" и, если её правда нет, падать
        // 400 "неизвестный ISO-код".
        if (isoList.length && isoList.indexOf(current) < 0) {
          selectCurrency(eqPickerCurrencies(null)[0].iso_code); // сам зовёт renderCurrencyPickerButton()+refreshPeriod()
        }
      })
      .catch(function () { /* справочник недоступен — молча остаёмся со значением по умолчанию */ });
  }

  // Перезапрос справочника после записи валюты (POST/PATCH/DELETE
  // /api/currencies*, design D3): сбросить его ключ в reportsCache (с
  // as_user_id или без — все варианты) и загрузить заново тем же
  // loadCurrencies(). Ответ записи несёт готовую строку, но перезапрос
  // заодно подтягивает правки с телефона и не дублирует на клиенте правило
  // wallet-report "своя валюта перекрывает общую".
  function reloadCurrencyDirectory() {
    Object.keys(reportsCache).forEach(function (k) {
      if (k.indexOf('currencies?') === 0) delete reportsCache[k];
    });
    return loadCurrencies();
  }

  function addDays(date, days) {
    var d = new Date(date.getTime());
    d.setDate(d.getDate() + days);
    return d;
  }

  // "Обзор" (Design/.../Отчёты - веб.dc.html, экран "обзор", по прямому
  // запросу — БЕЗ групп категорий и БЕЗ "обязательных платежей", пользователь
  // явно исключил оба). Заменил прежние отдельные таблицы "Баланс на начало
  // дня"/"Доход"/"Расход" целиком — тем же приёмом простоты, что и остальной
  // этот экран (без графических библиотек, полосы/столбцы — обычные div'ы).

  var MONTH_ABBR = ['янв', 'фев', 'мар', 'апр', 'май', 'июн', 'июл', 'авг', 'сен', 'окт', 'ноя', 'дек'];
  var WEEKDAY_ABBR = ['Пн', 'Вт', 'Ср', 'Чт', 'Пт', 'Сб', 'Вс'];

  function kpiChipHtml(nowStr, beforeStr, goodDirection) {
    // goodDirection: 'up' — рост хороший (доход/итог), 'down' — рост плохой
    // (расход). before === null — сравнение выключено (cmp-mode "none"),
    // чипа не показываем вовсе, а не "0%" — это не то же самое, что "не изменилось".
    if (beforeStr === null || beforeStr === undefined) return '';
    var before = parseFloat(beforeStr);
    var now = parseFloat(nowStr);
    if (!(before > 0)) return ''; // от нуля/отрицательного % не посчитать осмысленно
    var pct = ((now - before) / before) * 100;
    var isGood = goodDirection === 'up' ? pct >= 0 : pct <= 0;
    var sign = pct > 0 ? '+' : '';
    return (
      '<span class="kpi-chip ' + (isGood ? 'chip-good' : 'chip-bad') + '">' +
      sign + Math.round(pct) + '%</span>'
    );
  }

  function kpiTileHtml(label, value, chipHtml, sub) {
    return (
      '<div class="kpi-tile">' +
      '<div class="kpi-label">' + escapeHtml(label) + '</div>' +
      '<div class="kpi-value">' + value + '</div>' +
      '<div class="kpi-foot">' + chipHtml + '<span class="kpi-sub">' + escapeHtml(sub) + '</span></div>' +
      '</div>'
    );
  }

  function renderOverviewKpis(income, expense, balance, cmpIncome, cmpExpense) {
    var el = document.getElementById('overview-kpis');
    var itogNow = parseFloat(income.total_eq) - parseFloat(expense.total_eq);
    var itogNowStr = (itogNow < 0 ? '−' : '') + fmtEq(Math.abs(itogNow).toFixed(2));
    var itogChip = '';
    if (cmpIncome && cmpExpense) {
      var itogBefore = parseFloat(cmpIncome.total_eq) - parseFloat(cmpExpense.total_eq);
      itogChip = kpiChipHtml(String(itogNow), String(itogBefore), 'up');
    }
    el.innerHTML =
      kpiTileHtml('Расход', (expense.incomplete ? '~ ' : '') + fmtEq(expense.total_eq),
        kpiChipHtml(expense.total_eq, cmpExpense ? cmpExpense.total_eq : null, 'down'), 'за период') +
      kpiTileHtml('Доход', (income.incomplete ? '~ ' : '') + fmtEq(income.total_eq),
        kpiChipHtml(income.total_eq, cmpIncome ? cmpIncome.total_eq : null, 'up'), 'за период') +
      kpiTileHtml('Итог', itogNowStr, itogChip, 'доход минус расход') +
      kpiTileHtml('Остаток', (balance.incomplete ? '~ ' : '') + fmtEq(balance.total_eq), '',
        // total_eq с capital-assets — только ликвидные; ненулевой capital_eq
        // говорит, что часть денег — в активах (нет поля — старый сервер).
        parseFloat(balance.capital_eq) ? 'на конец периода, без капитала' : 'на конец периода');
  }

  // Столбцы кликабельны (по прямому запросу — "если мы выбрали какой-то
  // месяц, то мы даём детали по нему из соответствующего отчёта", для этой
  // панели это "Динамика") — клик зовёт goToMonthDetail (см. ниже, у
  // "Динамики": пушит текущее состояние "Отчётов" в историю, переключает
  // вкладку и сразу выбирает ТОТ ЖЕ бакет там). Окно этой панели теперь —
  // ВЕСЬ выбранный period-from/-to (по прямому запросу, 2026-09-11: "в
  // обзоре почему-то всегда 12 месяцев" — было ФИКСИРОВАННОЕ окно в 12
  // месяцев, назависимое от периода фильтра; см. историю refreshPeriod) —
  // строгое подмножество окна "Динамики" (у неё то же curFrom/curTo плюс
  // период сравнения ДО него, см. refreshDynamics), поэтому бакет,
  // кликабельный здесь, гарантированно уже есть в dynMonths.
  // balances — по прямому запросу ("добавь линией текущее состояние в
  // эквиваленте, сколько осталось после этого бакета"): по одному элементу
  // BalanceReport на каждый month в ТОМ ЖЕ порядке (см. refreshPeriod, откуда
  // приходит) — остаток на конец бакета, тот же смысл, что у KPI "Остаток"
  // (f_balance_to_date), просто на каждый бакет окна, а не только на
  // period-to. Необязателен (см. вызов ниже с пустым массивом, пока остатки
  // ещё грузятся) — тогда просто нет линии, бары рисуются как раньше.
  function renderOverviewMonthlyChart(data, balances) {
    var el = document.getElementById('overview-monthly-chart');
    var months = data.months;
    var groupBy = groupByValue();
    // Заголовок панели — по прямому запросу больше НЕ "· 12 месяцев" (тот
    // хвост был враньём мимо самого выбранного периода, см. историю выше) —
    // просто "Расход и доход по месяцам/неделям/дням", в зависимости от
    // группировки.
    var titleEl = document.getElementById('overview-monthly-title');
    if (titleEl) titleEl.textContent = 'Расход и доход по ' + GROUP_UNIT[groupBy].dat_pl;
    if (!months.length) {
      el.innerHTML = '<p class="wallet-empty">Нет данных.</p>';
      return;
    }
    var maxVal = 1;
    months.forEach(function (m) {
      maxVal = Math.max(maxVal, parseFloat(m.expense_eq) || 0, parseFloat(m.income_eq) || 0);
    });
    // Ни у баров, ни у точек остатка больше НЕТ своего title (по прямому
    // запросу — "более удобное решение вместо хинта": вертикальная линия +
    // один общий хинт под курсором вместо отдельной нативной подсказки на
    // каждый элемент, см. wireMonthlyChartCrosshair ниже) — курсор всё ещё
    // pointer/hover (.ov-bar-col в style.css), клик по-прежнему открывает
    // "Динамику" за этот бакет.
    var bars = months
      .map(function (m) {
        var expH = Math.round(((parseFloat(m.expense_eq) || 0) / maxVal) * 100);
        var incH = Math.round(((parseFloat(m.income_eq) || 0) / maxVal) * 100);
        return (
          '<div class="month-bar-col ov-bar-col" data-month="' + m.month_start + '">' +
          '<div class="month-bars">' +
          '<div class="month-bar expense" style="height:' + expH + '%"></div>' +
          '<div class="month-bar income" style="height:' + incH + '%"></div>' +
          '</div>' +
          '<div class="month-label">' + bucketAxisLabel(m.month_start, groupBy) + '</div>' +
          '</div>'
        );
      })
      .join('');
    var hasBalanceLine = balances && balances.length === months.length;
    // Линия капитала — только вместе с линией остатка: остатки не подошли
    // (401, число бакетов не совпало) — нет обеих.
    var hasCapital = hasBalanceLine && hasCapitalLine(balances);
    // Медиана — по прямому запросу ("линией на график, медиану на траты и
    // доход"): в отличие от остатка (см. комментарий про его НЕЗАВИСИМУЮ
    // шкалу чуть ниже) медиана расхода/дохода — величина ТОГО ЖЕ порядка,
    // что и сами бары, и ложится на их общую шкалу (maxVal) без отдельной
    // нормализации. На одной точке медиана вырожденная (совпадает с этим
    // единственным баром) — линия смысла не несёт, поэтому прячем её и из
    // графика, и из легенды.
    var hasMedianLines = months.length >= 2;
    var expenseVals = months.map(function (m) { return parseFloat(m.expense_eq) || 0; });
    var incomeVals = months.map(function (m) { return parseFloat(m.income_eq) || 0; });
    var medians = hasMedianLines ? { expense: median(expenseVals), income: median(incomeVals) } : null;
    // σ — по прямому запросу ("среднеквадратичное отклонение по обоим
    // показателям в обзор"), после обсуждения — полупрозрачная полоса ±σ
    // ВОКРУГ СРЕДНЕГО (см. renderStdDevBands), не вокруг медианы: это два
    // разных центра, mean тут посчитан только ради этой полосы, отдельно на
    // графике не показан.
    var means = hasMedianLines ? { expense: mean(expenseVals), income: mean(incomeVals) } : null;
    var stdevs = hasMedianLines
      ? { expense: stddev(expenseVals, means.expense), income: stddev(incomeVals, means.income) }
      : null;
    var notes = [];
    if (data.incomplete) notes.push('~ у части периода не нашёлся курс, суммы занижены');
    if (hasMedianLines) notes.push('Полупрозрачная область — разброс ±σ вокруг среднего.');
    el.innerHTML =
      '<div class="chart-legend"><span><span class="legend-dot expense"></span>расход</span>' +
      '<span><span class="legend-dot income"></span>доход</span>' +
      (hasBalanceLine ? '<span><span class="legend-dot balance"></span>остаток на конец периода</span>' : '') +
      (hasCapital ? CAPITAL_LEGEND_HTML : '') +
      (hasMedianLines
        ? '<span><span class="legend-line expense"></span>медиана расхода</span>' +
          '<span><span class="legend-line income"></span>медиана дохода</span>'
        : '') +
      '</div>' +
      '<div class="month-chart">' + bars + '</div>' +
      (notes.length ? '<div class="treemap-note">' + notes.join(' ') + '</div>' : '');

    Array.prototype.forEach.call(el.querySelectorAll('.ov-bar-col'), function (colEl) {
      colEl.addEventListener('click', function () {
        goToMonthDetail(colEl.getAttribute('data-month'));
      });
    });

    // Своя (не общая с барами) шкала — остаток копится годами и почти
    // всегда на порядки больше/меньше месячного расхода/дохода: на шкале
    // баров линия легла бы плоской либо вовсе за краем графика (та же
    // причина, по которой линию "среднее за 3" из дизайна в своё время НЕ
    // перенесли на "Динамику" — см. её раздел ниже, куда позже добавили ТУ
    // ЖЕ линию остатка, но уже со своей независимой шкалой, а не общей с
    // барами) — здесь читается только ФОРМА (растёт/падает остаток), точное
    // число — в общем хинте под курсором.
    var chartEl = el.querySelector('.month-chart');
    thinAxisLabels(chartEl); // ДО оверлеев — плотный режим меняет раскладку столбцов, см. её комментарий
    if (hasBalanceLine) renderMonthlyBalanceLine(chartEl, '.ov-bar-col', months, balances);
    if (hasCapital) renderMonthlyBalanceLine(chartEl, '.ov-bar-col', months, balances, 'capital_eq', 'capital');
    if (hasMedianLines) {
      // Полоса ±σ — ДО пунктира медианы (см. комментарий у renderStdDevBands
      // про порядок position:absolute оверлеев): иначе пунктир потерялся бы
      // под полупрозрачной заливкой.
      renderStdDevBands(
        chartEl, '.ov-bar-col',
        [
          { lo: means.expense - stdevs.expense, hi: means.expense + stdevs.expense, cls: 'expense' },
          { lo: means.income - stdevs.income, hi: means.income + stdevs.income, cls: 'income' },
        ],
        maxVal);
      renderMedianLines(
        chartEl, '.ov-bar-col',
        [{ value: medians.expense, cls: 'expense' }, { value: medians.income, cls: 'income' }],
        maxVal);
    }
    wireMonthlyChartCrosshair(chartEl, '.ov-bar-col', months, hasBalanceLine ? balances : null, groupBy, medians, stdevs);
  }

  // Прореживание подписей оси X (по прямому запросу, 2026-09-22: "два года
  // по дням/неделям — подписи налезают друг на друга") — подпись по-прежнему
  // рендерится у КАЖДОГО столбца (точная дата бакета всё равно в хинте под
  // курсором), но видимой остаётся только каждая step-я: step — сколько
  // столбцов занимает самая широкая подпись плюс зазор. Скрытые —
  // visibility:hidden, не display:none: высота строки подписей не должна
  // меняться, от неё считают геометрию оверлеи (barsAreaGeometry,
  // renderMonthlyBalanceLine). Считается по РЕАЛЬНОЙ ширине графика, поэтому
  // через ResizeObserver: "Динамика"/"Категории" рисуются, пока их вкладка
  // скрыта (ширина 0) — observer сработает, когда вкладка станет видимой, и
  // заодно на ресайз окна/сворачивание сайдбара. Старый observer
  // перерисованного графика отключаем сами — его chartEl уже выкинут из DOM.
  //
  // Заодно — "плотный" режим по числу столбцов: обычный зазор 6px между
  // столбцами (.month-chart) на 730 днях — это ~4400px одних зазоров, график
  // вылезал за край. Решается по ЧИСЛУ столбцов, не по ширине — чтобы
  // раскладка не прыгала на ресайзе и оверлеи (линия остатка, медианы),
  // посчитанные один раз после этой функции, с ней совпадали.
  var AXIS_LABEL_GAP_PX = 8;
  var CHART_DENSE_COLS = 40;
  var CHART_ULTRA_DENSE_COLS = 200;

  function thinAxisLabels(chartEl) {
    var host = chartEl.parentNode;
    if (host._axisLabelsObserver) host._axisLabelsObserver.disconnect();
    var labels = chartEl.querySelectorAll('.month-label');
    chartEl.classList.toggle('month-chart-dense', labels.length >= CHART_DENSE_COLS);
    chartEl.classList.toggle('month-chart-ultra-dense', labels.length >= CHART_ULTRA_DENSE_COLS);
    if (labels.length < 2) return;

    function apply() {
      if (!chartEl.clientWidth) return; // вкладка скрыта — дождёмся, когда станет видимой
      var maxLabelW = 0;
      Array.prototype.forEach.call(labels, function (l) { maxLabelW = Math.max(maxLabelW, l.offsetWidth); });
      // Шаг столбцов (ширина + зазор) — из реальной раскладки, не width/n:
      // зазор между столбцами зависит от плотного режима выше.
      var pitch = labels[1].parentNode.offsetLeft - labels[0].parentNode.offsetLeft;
      if (pitch <= 0) return;
      var step = Math.max(1, Math.ceil((maxLabelW + AXIS_LABEL_GAP_PX) / pitch));
      Array.prototype.forEach.call(labels, function (l, i) {
        l.classList.toggle('month-label-hidden', i % step !== 0);
      });
    }

    apply();
    if (typeof ResizeObserver === 'undefined') return;
    var observer = new ResizeObserver(apply);
    observer.observe(chartEl);
    host._axisLabelsObserver = observer;
  }

  // Медиана — простое arr.slice().sort() по числу; на длинах графика (12-24
  // точки) это дёшево, отдельного алгоритма отбора медианы за O(n) не нужно.
  function median(values) {
    var sorted = values.slice().sort(function (a, b) { return a - b; });
    var n = sorted.length;
    if (!n) return 0;
    var mid = Math.floor(n / 2);
    return n % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
  }

  function mean(values) {
    if (!values.length) return 0;
    return values.reduce(function (a, v) { return a + v; }, 0) / values.length;
  }

  // Среднеквадратичное отклонение — ГЕНЕРАЛЬНАЯ дисперсия (делим на n, не на
  // n-1): окно графика — это не выборка из чего-то большего, а вся
  // совокупность, которую видит эта карточка (по прямому запросу —
  // "среднеквадратичное отклонение по обоим показателям в обзор"; полоса
  // ±σ вокруг СРЕДНЕГО, см. её отрисовку — renderStdDevBands). avg —
  // необязательный, чтобы не считать mean() дважды, если он уже под рукой у
  // вызывающего кода.
  function stddev(values, avg) {
    if (!values.length) return 0;
    var m = avg === undefined ? mean(values) : avg;
    var variance = values.reduce(function (a, v) { return a + (v - m) * (v - m); }, 0) / values.length;
    return Math.sqrt(variance);
  }

  // Геометрия "область реальных баров внутри chartEl", общая для оверлеев,
  // что ложатся на ТУ ЖЕ шкалу, что и сами бары (медиана, полоса ±σ) — не
  // на всю высоту chartEl.clientHeight (ниже нее в столбце ещё сидит
  // .month-label, см. подробности в renderMonthlyBalanceLine, у неё
  // геометрия не вынесена сюда — там ещё своя независимая нормализация по
  // min/max с паддингами, общего с этой парой не так много).
  function barsAreaGeometry(chartEl, colSelector) {
    if (!chartEl) return null;
    var cols = chartEl.querySelectorAll(colSelector);
    var w = chartEl.clientWidth, h = chartEl.clientHeight;
    if (!cols.length || !w || !h) return null;
    var barsEl = cols[0].querySelector('.month-bars');
    if (!barsEl) return null;
    var containerRect = chartEl.getBoundingClientRect();
    var barsRect = barsEl.getBoundingClientRect();
    return { w: w, h: h, top: barsRect.top - containerRect.top, bottom: barsRect.bottom - containerRect.top };
  }

  // Пунктирные линии медианы поверх уже отрисованных баров — SVG-оверлей по
  // РЕАЛЬНОМУ layout (см. barsAreaGeometry), значение — в тех же единицах,
  // что и maxVal баров (value/maxVal), без отдельной нормализации по
  // min/max, как у остатка.
  //
  // lines — массив {value, cls} (не фиксированная пара expense/income): на
  // "Обзоре"/"Динамике" их две (расход+доход, cls совпадает с классом бара и
  // .month-chart-median-svg line.<cls> в style.css), на "Категориях во
  // времени" — всего одна серия (расход), вторая линия там попросту не о
  // чем — категория не про доход. Значения уже посчитаны снаружи (см.
  // renderOverviewMonthlyChart/renderDynamicsChart/renderCatsChart — тот же
  // объект уходит и в соответствующий хинт-крестик, чтобы не считать медиану
  // дважды).
  function renderMedianLines(chartEl, colSelector, lines, maxVal) {
    if (!lines.length) return;
    var g = barsAreaGeometry(chartEl, colSelector);
    if (!g) return;

    function y(v) { return g.bottom - Math.min(Math.max(v, 0) / maxVal, 1) * (g.bottom - g.top); }

    var svgLines = lines
      .map(function (ln) {
        var yy = y(ln.value).toFixed(1);
        return '<line class="' + ln.cls + '" x1="0" y1="' + yy + '" x2="' + g.w + '" y2="' + yy + '"></line>';
      })
      .join('');

    var wrap = document.createElement('div');
    wrap.innerHTML = '<svg class="month-chart-median-svg" width="' + g.w + '" height="' + g.h + '">' + svgLines + '</svg>';
    chartEl.appendChild(wrap.firstChild);
  }

  // Полупрозрачная полоса ±σ вокруг среднего — по прямому запросу
  // ("среднеквадратичное отклонение по обоим показателям в обзор"), после
  // обсуждения вариантов — вместо чисел в хинте выбрали именно полосу:
  // "разброс виден на глаз". Та же общая геометрия (barsAreaGeometry), что и
  // у renderMedianLines — полоса и пунктир медианы ложатся на одну шкалу.
  // Рисуется ДО renderMedianLines (см. вызовы) — оба оверлея position:absolute
  // и красятся поверх статичных .month-bar-col независимо от порядка в DOM
  // (так уже работали остаток/медиана), а вот МЕЖДУ СОБОЙ порядок положенных
  // друг на друга position:absolute важен: полоса должна лечь ПОД пунктиром
  // медианы, а не поверх — иначе пунктир потерялся бы под полупрозрачной
  // заливкой. bands — {lo, hi, cls}[], lo/hi уже посчитаны снаружи
  // (mean∓stddev), clamp по 0..maxVal — общий с барами (y() тот же, что в
  // renderMedianLines).
  function renderStdDevBands(chartEl, colSelector, bands, maxVal) {
    if (!bands.length) return;
    var g = barsAreaGeometry(chartEl, colSelector);
    if (!g) return;

    function y(v) { return g.bottom - Math.min(Math.max(v, 0) / maxVal, 1) * (g.bottom - g.top); }

    var rects = bands
      .map(function (b) {
        var yTop = y(b.hi), yBottom = y(b.lo);
        return '<rect class="' + b.cls + '" x="0" y="' + yTop.toFixed(1) + '" width="' + g.w +
          '" height="' + (yBottom - yTop).toFixed(1) + '"></rect>';
      })
      .join('');

    var wrap = document.createElement('div');
    wrap.innerHTML = '<svg class="month-chart-band-svg" width="' + g.w + '" height="' + g.h + '">' + rects + '</svg>';
    chartEl.appendChild(wrap.firstChild);
  }

  // SVG поверх уже отрисованных flex-баров, координаты — из РЕАЛЬНОГО
  // layout (getBoundingClientRect каждого столбца), а не расчёта вручную по
  // ширине/gap/паддингам flex-контейнера — тот же приём "не пересчитывать
  // руками то, что уже посчитал браузер", что и el.clientWidth в
  // squarifyTreemap. Только сама линия + точки — числа теперь в общем хинте
  // (wireMonthlyChartCrosshair), не в title/<title> отдельных элементов.
  //
  // colSelector — класс кликабельных столбцов ЭТОГО графика (".ov-bar-col"
  // на "Обзоре", ".dyn-bar-col" на "Динамике", по прямому запросу — та же
  // линия остатка добавлена и туда): одна функция на оба места, а не две
  // копии одной и той же геометрии под разным именем класса.
  //
  // field/cls (capital-assets, design D6) — какое поле бакета рисовать и
  // какой модификатор класса дать SVG: по умолчанию total_eq (остаток,
  // ликвидные кошельки); вторая линия — capital_eq с классом 'capital'
  // (пунктир). Шкала у каждой линии своя — капитал на порядки больше
  // ликвидных, на общей шкале линия остатка схлопнулась бы.
  function renderMonthlyBalanceLine(chartEl, colSelector, months, balances, field, cls) {
    field = field || 'total_eq';
    if (!chartEl) return;
    var cols = chartEl.querySelectorAll(colSelector);
    var w = chartEl.clientWidth, h = chartEl.clientHeight;
    // Контейнер невидим (см. renderTreemapIfVisible — тот же случай, вкладка
    // ещё не показана) или разметка почему-то разъехалась с данными —
    // рисовать не по чему, оставляем бары без линии, а не кривую линию.
    if (!cols.length || cols.length !== balances.length || !w || !h) return;

    var barsEl = cols[0].querySelector('.month-bars');
    if (!barsEl) return;

    var containerRect = chartEl.getBoundingClientRect();
    // Область, где реально стоят бары (НЕ вся высота .month-chart целиком —
    // ниже неё в том же столбце ещё сидит .month-label, см. её раздел в
    // README, "иногда уходит ниже оси времени"): раньше линия нормализовалась
    // на всю h = chartEl.clientHeight, а .month-bars реально занимает МЕНЬШЕ
    // — остаток близкий к минимуму окна рисовался ниже настоящего низа
    // баров, прямо под подписью месяца. .month-bars — ровно те же
    // getBoundingClientRect(), что и у самих столбцов ниже, не константа "на
    // глаз"; одного столбца достаточно — все .month-bar-col в ряду имеют
    // одинаковую высоту .month-bars (общий .month-chart, общая разметка).
    var barsRect = barsEl.getBoundingClientRect();
    var barsTop = barsRect.top - containerRect.top;
    var barsBottom = barsRect.bottom - containerRect.top;

    var vals = balances.map(function (b) { return parseFloat(b[field]) || 0; });
    var minV = Math.min.apply(null, vals);
    var maxV = Math.max.apply(null, vals);
    var span = maxV - minV || 1; // все 12 остатков равны — не делить на 0, просто ровная линия
    var padTop = 6, padBottom = 6; // небольшой запас сверху/снизу самой области баров

    var points = Array.prototype.map.call(cols, function (col, i) {
      var r = col.getBoundingClientRect();
      var x = r.left - containerRect.left + r.width / 2;
      var norm = (vals[i] - minV) / span; // 0 — минимум окна, 1 — максимум
      var y = barsTop + padTop + (1 - norm) * (barsBottom - barsTop - padTop - padBottom);
      return { x: x, y: y };
    });

    var circles = points
      .map(function (p) {
        return '<circle cx="' + p.x.toFixed(1) + '" cy="' + p.y.toFixed(1) + '" r="3"></circle>';
      })
      .join('');
    var polylinePoints = points.map(function (p) { return p.x.toFixed(1) + ',' + p.y.toFixed(1); }).join(' ');

    var wrap = document.createElement('div');
    wrap.innerHTML =
      '<svg class="month-chart-balance-svg' + (cls ? ' month-chart-balance-svg-' + cls : '') +
      '" width="' + w + '" height="' + h + '">' +
      '<polyline points="' + polylinePoints + '"></polyline>' + circles + '</svg>';
    chartEl.appendChild(wrap.firstChild);
  }

  // Линия капитала (capital-assets) — только если хотя бы в одном бакете
  // capital_eq ненулевой; нет поля (старый wallet-report) — линии нет.
  function hasCapitalLine(balances) {
    return !!balances && balances.some(function (b) { return parseFloat(b.capital_eq) > 0 || parseFloat(b.capital_eq) < 0; });
  }

  var CAPITAL_LEGEND_HTML = '<span><span class="legend-dot capital"></span>капитал на конец периода</span>';

  // Крестик-курсор (по прямому запросу — "вместо хинта: наведя мышку
  // вертикальная линия и сразу хинт со значениями, всеми за наведённое
  // время") — ОДИН общий хинт на весь столбец под курсором, а не отдельная
  // нативная всплывашка (title) на каждый бар по отдельности: та появляется
  // с задержкой браузера, эта — сразу при движении мыши. Общий движок для
  // ЛЮБОГО столбчатого графика (.month-chart/.month-bar-col разметка) —
  // tooltipHtml(i) строит содержимое хинта для i-го столбца, сам движок не
  // знает, что внутри (расход/доход/остаток на "Обзоре" и "Динамике",
  // расход по дню недели ниже, и т.д.), а не копия одного и того же кода
  // геометрии под каждый график.
  //
  // Ищет БЛИЖАЙШИЙ столбец к курсору (а не "курсор внутри столбца") — так
  // хинт всегда что-то показывает, даже если мышь на gap между барами или
  // чуть вылезла за край крайнего столбца.
  function wireChartCrosshair(chartEl, colSelector, tooltipHtml) {
    if (!chartEl) return;
    var cols = chartEl.querySelectorAll(colSelector);
    if (!cols.length) return;

    var line = document.createElement('div');
    line.className = 'month-chart-crosshair';
    line.hidden = true;
    var tip = document.createElement('div');
    tip.className = 'month-chart-tooltip';
    tip.hidden = true;
    chartEl.appendChild(line);
    chartEl.appendChild(tip);

    // Пересчитывается на каждое движение мыши, не кэшируется — те же
    // getBoundingClientRect, что и у линии остатка, но здесь дёшево:
    // единицы-десятки столбцов, не сотни.
    chartEl.addEventListener('mousemove', function (ev) {
      var rect = chartEl.getBoundingClientRect();
      var mouseX = ev.clientX - rect.left;
      var bestI = 0, bestDist = Infinity, bestX = 0;
      Array.prototype.forEach.call(cols, function (col, i) {
        var r = col.getBoundingClientRect();
        var x = r.left - rect.left + r.width / 2;
        var dist = Math.abs(x - mouseX);
        if (dist < bestDist) { bestDist = dist; bestI = i; bestX = x; }
      });

      line.style.left = bestX.toFixed(1) + 'px';
      line.hidden = false;

      tip.innerHTML = tooltipHtml(bestI);
      tip.hidden = false;
      // Хинт справа от линии, но не дальше правого края графика (иначе для
      // последних столбцов окна он вылезал бы за пределы карточки) — ширину
      // самого хинта браузер уже посчитал (только что вставили innerHTML),
      // clientWidth здесь настоящий, не расчёт вручную.
      var tipW = tip.clientWidth;
      var left = bestX + 10;
      if (left + tipW > rect.width) left = bestX - tipW - 10;
      tip.style.left = Math.max(0, left).toFixed(1) + 'px';
    });
    chartEl.addEventListener('mouseleave', function () {
      line.hidden = true;
      tip.hidden = true;
    });
  }

  // ОДИН общий хинт на весь столбец (расход, доход, остаток и медиана, если
  // они есть), а не отдельная всплывашка на каждый бар/точку по отдельности.
  // balances — null, если линии остатка ещё/вовсе нет (см. вызов выше) —
  // тогда хинт просто без строки "Остаток"; medians — тот же {expense,
  // income}, что уже ушёл в renderMedianLines (по прямому запросу — "точные
  // числа медиан тоже в хинт", раз сама линия на глаз даёт только форму, а
  // не число). colSelector — тот же смысл, что и в renderMonthlyBalanceLine
  // выше: ".ov-bar-col" на "Обзоре", ".dyn-bar-col" на "Динамике".
  // stdevs — необязательный {expense, income} (σ от среднего, см.
  // renderStdDevBands) — по прямому запросу ("в хинт это отклонение тоже
  // положи") СВОИМИ строками, со значком полосы (.legend-band — тот же
  // цвет, что у самой заливки на графике), а не дописан в строку медианы:
  // так σ читается как отдельная характеристика, а не довесок к медиане, и
  // сам значок отличим от пунктира median на глаз.
  function wireMonthlyChartCrosshair(chartEl, colSelector, months, balances, groupBy, medians, stdevs) {
    var withCapital = hasCapitalLine(balances); // строка «капитал» — только вместе с линией капитала
    wireChartCrosshair(chartEl, colSelector, function (i) {
      var m = months[i];
      var rows =
        '<div class="month-chart-tooltip-row"><span><span class="legend-dot expense"></span>расход</span>' +
        '<b>' + fmtEq(m.expense_eq) + '</b></div>' +
        '<div class="month-chart-tooltip-row"><span><span class="legend-dot income"></span>доход</span>' +
        '<b>' + fmtEq(m.income_eq) + '</b></div>';
      if (balances) {
        var b = balances[i];
        rows += '<div class="month-chart-tooltip-row"><span><span class="legend-dot balance"></span>остаток</span>' +
          '<b>' + (b.incomplete ? '~ ' : '') + fmtEq(b.total_eq) + '</b></div>';
        if (withCapital) {
          rows += '<div class="month-chart-tooltip-row"><span><span class="legend-dot capital"></span>капитал</span>' +
            '<b>' + (b.capital_incomplete ? '~ ' : '') + fmtEq(b.capital_eq) + '</b></div>';
        }
      }
      if (medians) {
        rows +=
          '<div class="month-chart-tooltip-row"><span><span class="legend-line expense"></span>медиана расхода</span>' +
          '<b>' + fmtEq(medians.expense.toFixed(2)) + '</b></div>' +
          '<div class="month-chart-tooltip-row"><span><span class="legend-line income"></span>медиана дохода</span>' +
          '<b>' + fmtEq(medians.income.toFixed(2)) + '</b></div>';
      }
      if (stdevs) {
        rows +=
          '<div class="month-chart-tooltip-row"><span><span class="legend-band expense"></span>σ расхода</span>' +
          '<b>± ' + fmtEq(stdevs.expense.toFixed(2)) + '</b></div>' +
          '<div class="month-chart-tooltip-row"><span><span class="legend-band income"></span>σ дохода</span>' +
          '<b>± ' + fmtEq(stdevs.income.toFixed(2)) + '</b></div>';
      }
      return '<div class="month-chart-tooltip-title">' + escapeHtml(bucketTooltipTitle(m.month_start, groupBy)) +
        '</div>' + rows;
    });
  }

  // Тот же быстрый хинт-крестик, что и на "Расход по месяцам" — по прямому
  // запросу ("хинт на графики всегда такой — быстрый, как в 'Расход по
  // месяцам'"), вместо нативного title с задержкой браузера, который тут
  // был раньше.
  function wireWeekdayChartCrosshair(chartEl, days) {
    wireChartCrosshair(chartEl, '.month-bar-col', function (i) {
      var d = days[i];
      return '<div class="month-chart-tooltip-title">' + escapeHtml(WEEKDAY_ABBR[d.isodow - 1]) + '</div>' +
        '<div class="month-chart-tooltip-row"><span><span class="legend-dot expense"></span>расход</span>' +
        '<b>' + fmtEq(d.expense_eq) + '</b></div>';
    });
  }

  // Тот же стандартный хинт-крестик — по прямому запросу ("Категории по
  // времени" тоже должны показывать линию и детали, как остальные графики):
  // раньше здесь был нативный title (см. историю renderCatsChart) с задержкой
  // браузера, вместо общего движка. monthly/keys — c.monthly/catsBuckets
  // текущей выбранной категории, тот же индекс i, что и у столбцов.
  function wireCatsChartCrosshair(chartEl, monthly, keys, groupBy, catMedian) {
    wireChartCrosshair(chartEl, '.month-bar-col', function (i) {
      var rows = '<div class="month-chart-tooltip-row"><span><span class="legend-dot expense"></span>расход</span>' +
        '<b>' + fmtEq(monthly[i].toFixed(2)) + '</b></div>';
      if (catMedian !== null && catMedian !== undefined) {
        rows += '<div class="month-chart-tooltip-row"><span><span class="legend-line expense"></span>медиана</span>' +
          '<b>' + fmtEq(catMedian.toFixed(2)) + '</b></div>';
      }
      return '<div class="month-chart-tooltip-title">' + escapeHtml(bucketTooltipTitle(keys[i], groupBy)) + '</div>' + rows;
    });
  }

  function renderOverviewWeekdayChart(data) {
    var el = document.getElementById('overview-weekday-chart');
    var days = data.days;
    if (!days.length) {
      el.innerHTML = '<p class="wallet-empty">Нет данных.</p>';
      return;
    }
    var maxVal = 1;
    days.forEach(function (d) { maxVal = Math.max(maxVal, parseFloat(d.expense_eq) || 0); });
    // Своего title у столбца больше нет (та же замена, что и на "Расход по
    // месяцам" — см. wireChartCrosshair): вместо нативной всплывашки с
    // задержкой браузера — общий быстрый хинт-крестик под курсором.
    var bars = days
      .map(function (d) {
        var h = Math.round(((parseFloat(d.expense_eq) || 0) / maxVal) * 100);
        var label = WEEKDAY_ABBR[d.isodow - 1];
        return (
          '<div class="month-bar-col">' +
          '<div class="month-bars"><div class="month-bar expense" style="height:' + h + '%"></div></div>' +
          '<div class="month-label">' + label + '</div></div>'
        );
      })
      .join('');
    el.innerHTML =
      '<div class="month-chart">' + bars + '</div>' +
      (data.incomplete ? '<div class="treemap-note">~ у части дней не нашёлся курс, суммы занижены</div>' : '');
    wireWeekdayChartCrosshair(el.querySelector('.month-chart'), days);
  }

  function renderOverviewBiggestMoves(data) {
    var el = document.getElementById('overview-moves');
    if (!data.rows.length) {
      el.innerHTML =
        '<p class="wallet-empty">Не из чего сравнивать — нет категорий с известной суммой в обоих периодах.</p>';
      return;
    }
    var maxAbs = 1;
    data.rows.forEach(function (r) {
      maxAbs = Math.max(maxAbs, Math.abs(parseFloat(r.amount_now_eq) - parseFloat(r.amount_before_eq)));
    });
    var rows = data.rows
      .map(function (r) {
        var delta = parseFloat(r.amount_now_eq) - parseFloat(r.amount_before_eq);
        var frac = Math.min(100, Math.round((Math.abs(delta) / maxAbs) * 100));
        // Левая половина (--inc-bar, "стали тратить меньше") заполняется при
        // delta<0, правая (--exp-bar, "стали тратить больше") — при delta>0.
        // Тот же приём и цвета, что в дизайне (m.wl/m.wr).
        var leftFill = delta < 0 ? '<div class="move-fill down" style="width:' + frac + '%"></div>' : '';
        var rightFill = delta > 0 ? '<div class="move-fill up" style="width:' + frac + '%"></div>' : '';
        var deltaText = (delta > 0 ? '+' : delta < 0 ? '−' : '') + fmtEq(Math.abs(delta).toFixed(2));
        var deltaCls = delta > 0 ? 'delta-up' : delta < 0 ? 'delta-down' : '';
        return (
          '<div class="move-row">' + categoryIconHtml(r.icon_sha256) +
          '<div class="move-info">' +
          '<div class="move-name">' + escapeHtml(r.account_name) + '</div>' +
          '<div class="move-bar"><div class="move-half left">' + leftFill + '</div>' +
          '<div class="move-divider"></div><div class="move-half right">' + rightFill + '</div></div>' +
          '</div>' +
          '<div class="move-delta ' + deltaCls + '">' + escapeHtml(deltaText) + '</div>' +
          '</div>'
        );
      })
      .join('');
    el.innerHTML =
      '<div class="moves-list">' + rows + '</div>' +
      (data.incomplete
        ? '<div class="treemap-note">~ у части категорий не нашёлся курс в одном из периодов</div>'
        : '');
  }

  // Мини-"Структура" на "Обзоре" — переиспользует уже загруженные данные
  // "Структуры расходов" (lastStructureData, см. refreshStructure), НЕ
  // отдельный запрос: обе вкладки грузятся одновременно при открытии
  // "Отчётов", это просто другое представление тех же данных. Может
  // сработать РАНЬШЕ, чем данные придут (если "Обзор" рисуется первым) —
  // тогда просто оставляет "Загрузка…", refreshStructure() перерисует сама,
  // когда данные будут готовы (см. её конец).
  function renderOverviewMiniStructure() {
    var el = document.getElementById('overview-mini-structure');
    if (!el || !lastStructureData) return;
    var cats = lastStructureData.categories.filter(function (c) {
      return c.amount_eq !== '' && parseFloat(c.amount_eq) > 0;
    });
    if (!cats.length) {
      el.innerHTML = '<p class="wallet-empty">Нет расходов за этот период.</p>';
      return;
    }
    var top = cats.slice(0, 5);
    var segHtml = top
      .map(function (c, i) {
        return (
          '<div title="' + escapeHtml(structureAreaHintTitle(c)) + '" style="width:' + (c.pct || 0) + '%;background:' +
          treemapTileColor(i) + '"></div>'
        );
      })
      .join('');
    var listHtml = top
      .map(function (c, i) {
        return (
          '<div class="mini-struct-row">' +
          '<span class="mini-struct-dot" style="background:' + treemapTileColor(i) + '"></span>' +
          '<span class="mini-struct-name">' + escapeHtml(c.account_name) + '</span>' +
          '<span class="mini-struct-pct">' + (c.pct !== null ? escapeHtml(c.pct) + '%' : '—') + '</span>' +
          '</div>'
        );
      })
      .join('');
    el.innerHTML = '<div class="mini-struct-bar">' + segHtml + '</div><div class="mini-struct-list">' + listHtml + '</div>';
  }

  // "Динамика" (бывш. "Динамика по месяцам", Design/.../Отчёты - веб.dc.html,
  // экран "dyn") — по прямому запросу, с переходом из "Обзора" ("Вся
  // динамика →"). Переименована и генерализована 2026-09-11 (по прямому
  // запросу — "аггрегировать не по месяцам, а по выбранному периоду
  // группировки"): окно графика раньше было ФИКСИРОВАННЫМ (24 месяца,
  // независимо от period-from/-to), теперь это сам выбранный период плюс
  // период сравнения ТОЙ ЖЕ длины перед ним (см. reportsWindowWithComparison
  // выше), разбитый на бакеты дня/недели/месяца — что выбрано в
  // #period-group (groupByValue). Данные — клиентская агрегация плоского
  // operations_for_period (тот же приём, что и у "Категорий", см.
  // sumIncomeExpenseByBucket выше — f_income_expense_by_month умела только
  // "по месяцу", больше не используется здесь); разбор выбранного бакета по
  // категориям — expense_structure_for_period (та же функция, что и вкладка
  // "Структура", cmp — предыдущий бакет) — по-прежнему ни одной новой
  // SQL-функции. Линия "Остаток на конец периода" — тот же приём и общие
  // renderMonthlyBalanceLine/wireMonthlyChartCrosshair, что и на "Обзоре".
  // Без линии "среднее за 3" из дизайна — тот же расход/доход по барам,
  // просто скользящее среднее, на их же шкале не то сравнение, ради
  // которого эта линия вообще нужна.

  var dynBuckets = []; // bucket_start combined-окна [prevFrom..curTo] — см. refreshDynamics
  var dynMonths = []; // {month_start, expense_eq, income_eq} на каждый dynBuckets[i] — см. refreshDynamics
  var dynSelectedMonth = null; // bucket_start ("YYYY-MM-DD") — какой столбец выбран сейчас
  var dynBalances = []; // по одному BalanceReport на каждый dynMonths[i] (см. refreshDynamics) — пусто, пока не дозагрузилось/не удалось
  var dynSplitIndex = 0; // индекс первого "текущего" (не приглушённого) бакета — см. bucketSplitIndex

  function lastDayOfMonth(monthStartStr) {
    var d = new Date(monthStartStr + 'T00:00:00');
    d.setMonth(d.getMonth() + 1);
    d.setDate(0); // 0-е число следующего месяца = последний день этого
    return isoDate(d);
  }

  function shiftMonth(monthStartStr, delta) {
    var d = new Date(monthStartStr + 'T00:00:00');
    d.setMonth(d.getMonth() + delta);
    d.setDate(1);
    return isoDate(d);
  }

  function renderDynamicsChart() {
    var el = document.getElementById('dyn-chart');
    var groupBy = groupByValue();
    var titleEl = document.getElementById('dyn-chart-title');
    if (titleEl) titleEl.textContent = 'Расход и доход по ' + GROUP_UNIT[groupBy].dat_pl;
    if (!dynMonths.length) {
      el.innerHTML = '<p class="wallet-empty">Нет данных.</p>';
      return;
    }
    var maxVal = 1;
    dynMonths.forEach(function (m) {
      maxVal = Math.max(maxVal, parseFloat(m.expense_eq) || 0, parseFloat(m.income_eq) || 0);
    });
    // Ни у одного столбца больше нет своего title — общий хинт под курсором
    // (см. wireMonthlyChartCrosshair) заменяет его целиком, тот же приём,
    // что и на "Обзоре". chart-bar-before — приглушённые столбцы периода
    // сравнения (i < dynSplitIndex, см. refreshDynamics/bucketSplitIndex) —
    // тот же общий класс, что и у "Категорий во времени".
    var bars = dynMonths
      .map(function (m, i) {
        var expH = Math.round(((parseFloat(m.expense_eq) || 0) / maxVal) * 100);
        var incH = Math.round(((parseFloat(m.income_eq) || 0) / maxVal) * 100);
        var label = bucketAxisLabel(m.month_start, groupBy);
        var selectedCls = m.month_start === dynSelectedMonth ? ' selected' : '';
        var beforeCls = i < dynSplitIndex ? ' chart-bar-before' : '';
        return (
          '<div class="month-bar-col dyn-bar-col' + selectedCls + beforeCls + '" data-month="' + m.month_start + '">' +
          '<div class="month-bars">' +
          '<div class="month-bar expense" style="height:' + expH + '%"></div>' +
          '<div class="month-bar income" style="height:' + incH + '%"></div>' +
          '</div>' +
          '<div class="month-label">' + label + '</div>' +
          '</div>'
        );
      })
      .join('');
    var hasBalanceLine = dynBalances.length === dynMonths.length;
    var hasCapital = hasBalanceLine && hasCapitalLine(dynBalances); // см. renderOverviewMonthlyChart
    // Медиана — тот же приём и та же общая пара renderMedianLines/
    // wireMonthlyChartCrosshair, что и на "Обзоре" (см. её раздел выше), по
    // ВСЕМУ окну графика целиком (текущий период + приглушённый период
    // сравнения), не только по текущему — та же логика, что у линии остатка
    // чуть ниже: одна общая шкала на весь ряд бакетов.
    var hasMedianLines = dynMonths.length >= 2;
    var dynMedians = hasMedianLines
      ? {
          expense: median(dynMonths.map(function (m) { return parseFloat(m.expense_eq) || 0; })),
          income: median(dynMonths.map(function (m) { return parseFloat(m.income_eq) || 0; })),
        }
      : null;
    el.innerHTML =
      '<div class="chart-legend"><span><span class="legend-dot expense"></span>расход</span>' +
      '<span><span class="legend-dot income"></span>доход</span>' +
      (hasBalanceLine ? '<span><span class="legend-dot balance"></span>остаток на конец периода</span>' : '') +
      (hasCapital ? CAPITAL_LEGEND_HTML : '') +
      (hasMedianLines
        ? '<span><span class="legend-line expense"></span>медиана расхода</span>' +
          '<span><span class="legend-line income"></span>медиана дохода</span>'
        : '') +
      '</div>' +
      '<div class="month-chart dyn-chart-wide">' + bars + '</div>' +
      (dynSplitIndex > 0
        ? '<div class="treemap-note">Приглушённые столбцы — период сравнения, той же длины, что и выбранный.</div>'
        : '');

    Array.prototype.forEach.call(el.querySelectorAll('.dyn-bar-col'), function (colEl) {
      colEl.addEventListener('click', function () {
        selectDynamicsMonth(colEl.getAttribute('data-month'));
      });
    });

    // Линия "Остаток на конец периода" — по прямому запросу, тот же приём и
    // те же общие renderMonthlyBalanceLine/wireMonthlyChartCrosshair, что и
    // на "Обзоре" (см. её раздел выше про собственную шкалу и общий хинт под
    // курсором вместо title на каждом элементе).
    var chartEl = el.querySelector('.month-chart');
    thinAxisLabels(chartEl); // ДО оверлеев — см. renderOverviewMonthlyChart
    if (hasBalanceLine) renderMonthlyBalanceLine(chartEl, '.dyn-bar-col', dynMonths, dynBalances);
    if (hasCapital) renderMonthlyBalanceLine(chartEl, '.dyn-bar-col', dynMonths, dynBalances, 'capital_eq', 'capital');
    if (hasMedianLines) {
      renderMedianLines(
        chartEl, '.dyn-bar-col',
        [{ value: dynMedians.expense, cls: 'expense' }, { value: dynMedians.income, cls: 'income' }],
        maxVal);
    }
    wireMonthlyChartCrosshair(chartEl, '.dyn-bar-col', dynMonths, hasBalanceLine ? dynBalances : null, groupBy, dynMedians);
  }

  // "Год к году" — по календарному году (по прямому запросу, остаётся как
  // отдельная, ОРТОГОНАЛЬНАЯ витрина независимо от группировки/длины
  // выбранного периода, см. её ответ в диалоге 2026-09-11): группирует
  // dynMonths (теперь — бакеты ЛЮБОЙ длины, см. refreshDynamics) по
  // календарному году простым slice(0,4) года из bucket_start — работает
  // для дня/недели/месяца одинаково, просто "весь год"/"частично" считается
  // не по числу бакетов (у недели/дня их совсем другое количество), а по
  // тому, докуда КАЛЕНДАРНО дотягивается последний бакет года (см.
  // bucketEnd ниже) относительно 31 декабря.
  function renderDynamicsYears() {
    var el = document.getElementById('dyn-years');
    var groupBy = groupByValue();
    var byYear = {};
    dynMonths.forEach(function (m) {
      var y = m.month_start.slice(0, 4);
      byYear[y] = (byYear[y] || 0) + (parseFloat(m.expense_eq) || 0);
    });
    var years = Object.keys(byYear).sort().reverse().slice(0, 3);
    if (!years.length) {
      el.innerHTML = '<p class="wallet-empty">Недостаточно данных.</p>';
      return;
    }
    var maxSum = 1;
    years.forEach(function (y) { maxSum = Math.max(maxSum, byYear[y]); });

    var rows = years
      .map(function (y) {
        var sum = byYear[y];
        var w = Math.round((sum / maxSum) * 100);
        var prevY = String(parseInt(y, 10) - 1);
        var chipHtml = '';
        if (byYear[prevY] !== undefined && byYear[prevY] > 0) {
          chipHtml = kpiChipHtml(String(sum), String(byYear[prevY]), 'down');
        }
        var bucketsOfYear = dynMonths.filter(function (m) { return m.month_start.slice(0, 4) === y; });
        var lastBucketOfYear = bucketsOfYear[bucketsOfYear.length - 1].month_start;
        var isFull = bucketEnd(lastBucketOfYear, groupBy) >= (y + '-12-31');
        var note = isFull ? 'весь год' : ('в выборке по ' + ruShortDate(bucketEnd(lastBucketOfYear, groupBy)));
        return (
          '<div class="dyn-year-row">' +
          '<div class="dyn-year-head"><span class="dyn-year-name">' + escapeHtml(y) + '</span>' +
          '<span class="dyn-year-sub">' + escapeHtml(note) + '</span>' + chipHtml + '</div>' +
          '<div class="dyn-year-bar-row"><div class="dyn-year-bar"><div class="dyn-year-bar-fill" style="width:' +
          w + '%"></div></div><div class="dyn-year-sum">' + fmtEq(sum.toFixed(2)) + '</div></div>' +
          '</div>'
        );
      })
      .join('');
    el.innerHTML = rows;
  }

  function dynStatHtml(label, valueHtml) {
    return (
      '<div class="dyn-stat"><div class="dyn-stat-label">' + escapeHtml(label) + '</div>' +
      '<div class="dyn-stat-value">' + valueHtml + '</div></div>'
    );
  }

  var RU_MONTH_FULL = [
    'январь', 'февраль', 'март', 'апрель', 'май', 'июнь',
    'июль', 'август', 'сентябрь', 'октябрь', 'ноябрь', 'декабрь',
  ];

  function renderDynamicsSelected(monthEntry, structData) {
    var el = document.getElementById('dyn-selected');
    var groupBy = groupByValue();
    var expenseNow = parseFloat(monthEntry.expense_eq) || 0;
    var incomeNow = parseFloat(monthEntry.income_eq) || 0;
    var itog = incomeNow - expenseNow;
    var itogStr = (itog < 0 ? '−' : '') + fmtEq(Math.abs(itog).toFixed(2));

    var prevStart = prevBucketStart(monthEntry.month_start, groupBy);
    var prevEntry = dynMonths.filter(function (m) { return m.month_start === prevStart; })[0];
    var prevChip = prevEntry ? kpiChipHtml(monthEntry.expense_eq, prevEntry.expense_eq, 'down') : '—';

    var catRows = structData.categories
      .slice(0, 6)
      .map(function (c) {
        var pct = c.pct === null || c.pct === undefined ? 0 : c.pct;
        return (
          '<div class="dyn-cat-row" data-account-uuid="' + c.account_uuid + '">' + categoryIconHtml(c.icon_sha256) +
          '<div class="dyn-cat-info"><div class="dyn-cat-name">' + escapeHtml(c.account_name) + '</div>' +
          '<div class="reports-bar"><div class="reports-bar-fill" style="width:' + pct + '%"></div></div></div>' +
          '<div class="dyn-cat-sum">' + formatStructureAmount(c.amount_eq) + '</div>' +
          '<div class="dyn-cat-delta">' + ppDeltaHtml(c.pp_delta) + '</div>' +
          '</div>'
        );
      })
      .join('');

    el.innerHTML =
      '<div class="dyn-sel-name">' + escapeHtml(bucketTooltipTitle(monthEntry.month_start, groupBy)) + '</div>' +
      '<div class="dyn-sel-stats">' +
      dynStatHtml('Расход', fmtEq(monthEntry.expense_eq)) +
      dynStatHtml('Доход', fmtEq(monthEntry.income_eq)) +
      dynStatHtml('Итог', itogStr) +
      dynStatHtml('К пред. периоду', prevChip) +
      '</div>' +
      '<div class="dyn-sel-cats">' +
      (catRows || '<p class="wallet-empty">Нет расходов в этом периоде.</p>') +
      '</div>';

    // Клик по статье — переход на "Список операций", уже отфильтрованный на
    // ЭТОТ бакет и ЭТУ категорию (см. goToOperationsForCategory ниже, рядом
    // с goToMonthDetail — тот же приём "детализации"); границы бакета —
    // явно, а не подразумевая месяц внутри goToOperationsForCategory (та
    // теперь общая для любой группировки, см. её сигнатуру).
    var bucketEndStr = bucketEnd(monthEntry.month_start, groupBy);
    Array.prototype.forEach.call(el.querySelectorAll('.dyn-cat-row'), function (rowEl) {
      rowEl.addEventListener('click', function () {
        goToOperationsForCategory(monthEntry.month_start, bucketEndStr, rowEl.getAttribute('data-account-uuid'));
      });
    });
  }

  // Клик по столбцу графика — единственный НОВЫЙ запрос на этой вкладке
  // (разбор выбранного месяца по категориям); сам график и "Год к году"
  // уже целиком в dynMonths, второй раз не грузятся.
  function selectDynamicsMonth(monthStart) {
    dynSelectedMonth = monthStart;
    renderDynamicsChart(); // перерисовать — подсветить выбранный столбец

    var monthEntry = dynMonths.filter(function (m) { return m.month_start === monthStart; })[0];
    if (!monthEntry) return;

    var detailEl = document.getElementById('dyn-selected');
    detailEl.innerHTML = '<p class="sub">Загрузка…</p>';

    var groupBy = groupByValue();
    var monthEnd = bucketEnd(monthStart, groupBy);
    var prevStart = prevBucketStart(monthStart, groupBy);
    var prevEnd = bucketEnd(prevStart, groupBy);

    fetchReport('expense-structure', {
      from: monthStart + 'T00:00:00', to: monthEnd + 'T23:59:59',
      cmp_from: prevStart + 'T00:00:00', cmp_to: prevEnd + 'T23:59:59',
      eq_currency: eqCurrencyValue(),
    })
      .then(function (data) { if (data) renderDynamicsSelected(monthEntry, data); })
      .catch(function (err) {
        detailEl.innerHTML = reportsErrorHtml('Не удалось загрузить категории периода: ' + err.message);
      });
  }

  function refreshDynamics() {
    var chartEl = document.getElementById('dyn-chart');
    var yearsEl = document.getElementById('dyn-years');
    var selectedEl = document.getElementById('dyn-selected');
    [chartEl, yearsEl, selectedEl].forEach(function (el) { el.innerHTML = '<p class="sub">Загрузка…</p>'; });

    var fromStr = document.getElementById('period-from').value;
    var toStr = document.getElementById('period-to').value;
    var eq = eqCurrencyValue();
    var groupBy = groupByValue();

    // Окно — сам выбранный период плюс период сравнения ТОЙ ЖЕ длины ДО
    // него (по прямому запросу, 2026-09-11) — раньше здесь было
    // ФИКСИРОВАННОЕ окно в 24 месяца [12 сравнения + 12 текущих],
    // независимое от period-from/-to (см. reportsWindowWithComparison
    // выше — тот же computeCmpRange('prev', ...), что и у "Структуры").
    var win = reportsWindowWithComparison(fromStr, toStr);
    dynBuckets = buildBuckets(win.prevFrom, win.curTo, groupBy);
    dynSplitIndex = bucketSplitIndex(dynBuckets, win.curFrom);

    // Клиентская агрегация плоского operations_for_period — та же смена, что
    // и на "Обзоре" выше (f_income_expense_by_month умела только "по
    // месяцу"), см. sumIncomeExpenseByBucket.
    fetchAllOperations({ from: win.prevFrom + 'T00:00:00', to: win.curTo + 'T23:59:59', eq_currency: eq })
      .then(function (data) {
        if (!data) return null;
        var sums = sumIncomeExpenseByBucket(data.operations, dynBuckets, groupBy);
        dynMonths = dynBuckets.map(function (b, i) {
          return { month_start: b, expense_eq: sums.expense[i].toFixed(2), income_eq: sums.income[i].toFixed(2) };
        });
        dynBalances = [];
        renderDynamicsYears();
        if (!dynMonths.length) return renderDynamicsChart();
        // Остаток на конец КАЖДОГО бакета окна — GET /api/reports/balance-series
        // (по прямому запросу, 2026-09-11 — "новое API с шагом, а не вызов с
        // миллионом параметров в GET"): сервер сам строит границы бакетов из
        // from/to/step, тем же алгоритмом, что и клиентский buildBuckets —
        // batch.buckets[i] соответствует dynBuckets[i] один в один, без
        // явного списка дат (раньше — до сотен дат в query-параметре при
        // group-by "день"/"неделя" на широком периоде, упиралось в лимит
        // длины URI на гейтвее, см. историю чата).
        return fetchReport('balance-series', { from: win.prevFrom, to: win.curTo, step: groupBy, eq_currency: eq })
          .then(function (batch) {
            // 401 (renderLogin() уже сработал внутри fetchReport) — рисуем
            // хотя бы бары без линии остатка. batch.buckets[i] — та же форма
            // элемента ({accounts, total_eq, incomplete}), что раньше отдавал
            // batch.dates[i] у balance-at-dates, поэтому остальной код
            // ("Динамики") не меняется вовсе.
            dynBalances = batch ? batch.buckets : [];
            // Автовыбор — последний (самый свежий) бакет окна;
            // renderDynamicsChart() вызывается уже ВНУТРИ selectDynamicsMonth
            // (подсветка столбца, линия остатка и хинт — там же, см. её код).
            selectDynamicsMonth(dynMonths[dynMonths.length - 1].month_start);
          });
      })
      .catch(function (err) {
        chartEl.innerHTML = reportsErrorHtml('Не удалось загрузить динамику: ' + err.message);
      });
  }

  // Клик по столбцу "Расход по месяцам" на "Обзоре" (см.
  // renderOverviewMonthlyChart) — тот же переход, что и кнопка "Вся
  // динамика →", только сразу с выбранным месяцем. pushReportsHistory() (см.
  // ниже, у навигации сайдбара) запоминает состояние "Обзора" ДО перехода —
  // "Назад" вернёт именно фильтр и вкладку, какими они были в момент клика,
  // а не то, что окажется в полях к моменту, когда пользователь решит
  // вернуться (он мог успеть их поменять, разглядывая "Динамику").
  function goToMonthDetail(monthStart) {
    pushReportsHistory();
    switchReportsView('dyn');
    selectDynamicsMonth(monthStart);
  }

  // Клик по статье в разборе выбранного месяца на "Динамике" (см.
  // renderDynamicsSelected) — тот же приём "детализации", что и
  // goToMonthDetail выше: pushReportsHistory() ДО перехода запоминает
  // 'dyn' с фильтром шапки, каким он был у пользователя в этот момент (а
  // не то, во что превратится period-from/to ниже) — "Назад" из "Списка
  // операций" вернёт именно это состояние (см. goReportsBack), а второе
  // "Назад" — уже то, что запомнил сам goToMonthDetail, если в "Динамику"
  // пришли с "Обзора" ("Вся динамика →"/клик по столбцу): история — общий
  // стек на весь раздел "Отчёты", не привязанный к паре вкладок.
  //
  // period-from/to подменяются на границы ИМЕННО этого бакета (from/to —
  // явно от вызывающего, а не lastDayOfMonth() внутри: с группировкой
  // день/неделя/месяц конец периода — не всегда конец календарного месяца,
  // см. bucketEnd, вызывающие — renderDynamicsSelected/wireCatsEvents) —
  // период сравнения/эквивалентная валюта остаются те же, что были в шапке;
  // refreshOperations(categoryUuid) — единственное место, где "Список
  // операций" открывается уже с преднастроенным фильтром по категории,
  // а не с нуля (см. её комментарий).
  function goToOperationsForCategory(fromDateStr, toDateStr, categoryUuid) {
    pushReportsHistory();
    document.getElementById('period-from').value = fromDateStr;
    document.getElementById('period-to').value = toDateStr;
    updatePeriodSummary();
    switchReportsView('ops');
    refreshOperations(categoryUuid);
  }

  // Клик по строке кошелька на "Кошельках и остатках" (см. renderWalletRow) —
  // тот же приём "детализации", что и goToOperationsForCategory выше, только
  // период НЕ подменяется (в отличие от клика по месяцу "Динамики" — там
  // конкретный месяц имел смысл сузить период, здесь пользователь смотрит
  // операции ИМЕННО ТОГО периода, что уже был выбран на "Кошельках").
  function goToOperationsForWallet(walletUuid) {
    pushReportsHistory();
    switchReportsView('ops');
    refreshOperations(null, walletUuid);
  }

  // Один вызов на всё "Обзор" — общие period-from/period-to/eq-currency/
  // structure-cmp-mode (см. renderReports) уже читает refreshStructure() тем
  // же способом, здесь тот же приём просто применён к пяти панелям вместо одной.
  function refreshPeriod() {
    updatePeriodSummary();
    var kpisEl = document.getElementById('overview-kpis');
    var monthlyEl = document.getElementById('overview-monthly-chart');
    var movesEl = document.getElementById('overview-moves');
    var weekdayEl = document.getElementById('overview-weekday-chart');
    [kpisEl, monthlyEl, movesEl, weekdayEl].forEach(function (el) {
      el.innerHTML = '<p class="sub">Загрузка…</p>';
    });

    // Границы дня дописываются здесь, не переносятся на сервер: from/to —
    // обычные timestamp-параметры (см. openapi.yaml), <input type="date">
    // отдаёт только "yyyy-mm-dd" (полночь) — без T23:59:59 конец периода
    // молча исключил бы весь последний день.
    var eq = eqCurrencyValue();
    var fromStr = document.getElementById('period-from').value;
    var toStr = document.getElementById('period-to').value;
    var from = fromStr + 'T00:00:00';
    var to = toStr + 'T23:59:59';
    var groupBy = groupByValue();
    var cmpMode = document.getElementById('structure-cmp-mode').value;
    var cmpRange = computeCmpRange(cmpMode, fromStr, toStr);
    var cmpFrom = cmpRange ? isoDate(cmpRange.from) + 'T00:00:00' : null;
    var cmpTo = cmpRange ? isoDate(cmpRange.to) + 'T23:59:59' : null;

    // "Остаток на конец периода" — f_balance_to_date считает строго ДО даты
    // (см. reports_repo.hpp у balance_to_date), поэтому берём день ПОСЛЕ
    // periodTo, а не сам periodTo — иначе последний день периода бы не вошёл.
    var balanceDate = isoDate(addDays(new Date(toStr + 'T00:00:00'), 1));

    Promise.all([
      fetchReport('income', { from: from, to: to, eq_currency: eq }),
      fetchReport('expense', { from: from, to: to, eq_currency: eq }),
      fetchReport('balance', { date: balanceDate, eq_currency: eq }),
    ])
      .then(function (results) {
        var income = results[0], expense = results[1], balance = results[2];
        if (!income || !expense || !balance) return; // один из трёх — 401, renderLogin() уже вызван внутри fetchReport
        if (!cmpRange) {
          renderOverviewKpis(income, expense, balance, null, null);
          return null;
        }
        return Promise.all([
          fetchReport('income', { from: cmpFrom, to: cmpTo, eq_currency: eq }),
          fetchReport('expense', { from: cmpFrom, to: cmpTo, eq_currency: eq }),
        ]).then(function (cmpResults) {
          renderOverviewKpis(income, expense, balance, cmpResults[0], cmpResults[1]);
        });
      })
      .catch(function (err) {
        kpisEl.innerHTML = reportsErrorHtml('Не удалось загрузить обзор: ' + err.message);
      });

    // Расход по бакетам — по прямому запросу (2026-09-11: "в обзоре почему-то
    // всегда 12 месяцев"): раньше это была ФИКСИРОВАННАЯ витрина "последние
    // 12 месяцев, заканчивая periodTo", НЕЗАВИСИМО от period-from — теперь
    // окно = сам выбранный период (fromStr..toStr), бакеты — по выбранной
    // группировке (#period-group, groupByValue выше). f_income_expense_by_month
    // умела агрегировать только "по месяцу" — заменена клиентской
    // агрегацией плоского operations_for_period (тот же GET
    // /api/reports/operations, что и у "Списка операций"/"Категорий"), см.
    // sumIncomeExpenseByBucket выше — НИ ОДНОЙ новой SQL-функции.
    var overviewBuckets = buildBuckets(fromStr, toStr, groupBy);
    // Окно ЗАПРОСА операций — по прямому запросу ("правь все пункты по
    // нагрузке", дубли широкого окна между Обзором и Динамикой/Категориями):
    // то же prevFrom..curTo, что и у refreshDynamics/refreshCategories ниже
    // (reportsWindowWithComparison), а НЕ узкое fromStr..toStr самого
    // Обзора — при одинаковой строке запроса reportsInFlight (см. fetchReport)
    // отдаёт им ОДИН и тот же промис вместо трёх отдельных прогонов курсорной
    // пагинации по одному и тому же (почти) объёму данных. Агрегация ниже
    // (sumIncomeExpenseByBucket) при этом остаётся над overviewBuckets — тем
    // же УЗКИМ диапазоном, что и раньше: лишние строки периода сравнения она
    // и так молча игнорирует (bucketStart вне overviewBuckets — idx
    // undefined, см. её код), поэтому расширение окна ЗАПРОСА не меняет,
    // что реально попадёт в сами столбцы графика.
    var opsWin = reportsWindowWithComparison(fromStr, toStr);
    fetchAllOperations({ from: opsWin.prevFrom + 'T00:00:00', to: opsWin.curTo + 'T23:59:59', eq_currency: eq })
      .then(function (data) {
        if (!data) return null;
        if (!overviewBuckets.length) return renderOverviewMonthlyChart({ months: [], incomplete: false }, []);
        var sums = sumIncomeExpenseByBucket(data.operations, overviewBuckets, groupBy);
        var chartData = {
          months: overviewBuckets.map(function (b, i) {
            return { month_start: b, expense_eq: sums.expense[i].toFixed(2), income_eq: sums.income[i].toFixed(2) };
          }),
          incomplete: data.incomplete,
        };
        // Остаток на конец КАЖДОГО бакета (по прямому запросу — "линией
        // текущее состояние в эквиваленте") — GET /api/reports/balance-series
        // (по прямому запросу, 2026-09-11 — "новое API с шагом, а не вызов с
        // миллионом параметров в GET"): сервер сам строит границы бакетов из
        // from/to/step, тем же алгоритмом, что и клиентский buildBuckets —
        // batch.buckets[i] соответствует overviewBuckets[i] один в один, без
        // явного списка дат (раньше — до сотен дат при group-by "день" на
        // широком периоде, упиралось в лимит длины URI на гейтвее и падало
        // "Failed to fetch"). Один общий рендер после ответа, не бары сначала
        // и линия следом отдельным заходом — иначе график бы дважды
        // перерисовывался на глазах у пользователя.
        return fetchReport('balance-series', { from: fromStr, to: toStr, step: groupBy, eq_currency: eq })
          .then(function (batch) {
            // 401 (renderLogin() уже сработал внутри fetchReport) — рисуем
            // хотя бы бары без линии, а не оставляем "Загрузка…" висеть
            // навсегда. batch.buckets[i] — та же форма элемента ({accounts,
            // total_eq, incomplete}), что раньше отдавал batch.dates[i] у
            // balance-at-dates, поэтому renderOverviewMonthlyChart дальше не
            // меняется вовсе.
            renderOverviewMonthlyChart(chartData, batch ? batch.buckets : []);
          });
      })
      .catch(function (err) {
        monthlyEl.innerHTML = reportsErrorHtml('Не удалось загрузить расход по периодам: ' + err.message);
      });

    fetchReport('expense-by-weekday', { from: from, to: to, eq_currency: eq })
      .then(function (data) { if (data) renderOverviewWeekdayChart(data); })
      .catch(function (err) {
        weekdayEl.innerHTML = reportsErrorHtml('Не удалось загрузить ритм недели: ' + err.message);
      });

    // "Что изменилось" в принципе не из чего строить без периода сравнения —
    // не шлём запрос вовсе, а не отдаём его серверу отвечать 400.
    if (!cmpRange) {
      movesEl.innerHTML =
        '<p class="wallet-empty">Выберите период сравнения выше, чтобы увидеть, что изменилось сильнее всего.</p>';
    } else {
      fetchReport('expense-biggest-moves', {
        from: from, to: to, cmp_from: cmpFrom, cmp_to: cmpTo, eq_currency: eq, limit: 6,
      })
        .then(function (data) { if (data) renderOverviewBiggestMoves(data); })
        .catch(function (err) {
          movesEl.innerHTML = reportsErrorHtml('Не удалось загрузить изменения: ' + err.message);
        });
    }

    refreshStructure();
    refreshDynamics();
    refreshOperations();
    refreshCategories();
    refreshWalletBalances();
    refreshCapital();
  }

  // "Список операций" (Design/.../Отчёты - веб (офлайн).html, вид 'ops') —
  // GET /api/reports/operations отдаёт СТРАНИЦАМИ по 1000 (по прямому
  // запросу, 2026-09-12 — "если выбираем 20 лет, то нет необходимости
  // доставать всё"), без поиска/фильтров на сервере (см. reports_repo.hpp,
  // почему) — их делает этот блок над уже загруженными страницами, тем же
  // приёмом, что и design-прототип экрана держит ленту в памяти, просто
  // теперь лента растёт по частям, а не выгружается целиком одним запросом.
  //
  // Раскрытие "хвоста" списка — доскроллом до низа (infinite scroll, по
  // прямому запросу), не кнопкой "Показать ещё": сентинел внизу списка
  // (#ops-sentinel, см. wireOpsInfiniteScroll) сначала раскрывает уже
  // ЗАГРУЖЕННЫЕ, но ещё не показанные строки (opsState.limit += 60 — тот же
  // приём виртуального рендера, что был и раньше, просто без кнопки), а
  // когда локальный запас исчерпан и сервер сообщил has_more — подгружает
  // СЛЕДУЮЩУЮ страницу (см. loadMoreOperations).
  //
  // ВАЖНАЯ ОГОВОРКА (по прямому запросу, осознанно): чипы категорий/
  // кошельков (opsDistinctCategories/opsDistinctWallets) и поиск/фильтр
  // (opsMatchesFilter) построены по ТОМУ, что УЖЕ ЗАГРУЖЕНО (opsAll), а не
  // по всему периоду целиком — раньше, пока /operations отдавал всё одним
  // запросом, это было одно и то же; для широкого периода с узким фильтром
  // это значит, что редкая категория из давно прошедшей, ещё не догруженной
  // страницы не появится в чипах и не найдётся поиском, пока пользователь
  // не долистает до неё — обратная сторона того, что "20 лет" больше не
  // тянутся в браузер одним запросом целиком.

  var RU_MONTH_GEN = [
    'января', 'февраля', 'марта', 'апреля', 'мая', 'июня',
    'июля', 'августа', 'сентября', 'октября', 'ноября', 'декабря',
  ];

  var OPS_TYPES = [['all', 'Все'], ['expense', 'Расход'], ['income', 'Доход'], ['transfer', 'Переводы']];

  // Переоценка капитального актива (kind 'revaluation', change capital-assets):
  // пятый вариант переключателя — только если среди ЗАГРУЖЕННЫХ строк есть
  // хотя бы одна переоценка; на леджере без активов переключатель прежний.
  function opsTypes() {
    var hasReval = opsAll.some(function (r) { return r.kind === 'revaluation'; });
    return hasReval || opsState.type === 'revaluation'
      ? OPS_TYPES.concat([['revaluation', 'Переоценка']])
      : OPS_TYPES;
  }

  // Знак суммы строки: расход «−», доход «+»; переоценка — по направлению
  // (зачисление на актив, to_uuid === wallet_uuid, — вверх, «+»; списание с
  // актива — вниз, «−»); у перевода знака нет.
  function opsRowSign(r) {
    if (r.kind === 'expense') return '−';
    if (r.kind === 'income') return '+';
    if (r.kind === 'revaluation') return r.to_uuid === r.wallet_uuid ? '+' : '−';
    return '';
  }

  // Название строки, когда нет комментария: перевод — «A → B», переоценка —
  // «Переоценка: <актив>», иначе — категория.
  function opsRowTitle(r) {
    if (r.comment) return r.comment;
    if (r.kind === 'transfer') return r.from_name + ' → ' + r.to_name;
    if (r.kind === 'revaluation') return 'Переоценка: ' + r.wallet_name;
    return r.category_name;
  }

  // Операции ВСЕХ уже загруженных страниц (как пришли от сервера, ORDER BY
  // date DESC — тот же порядок, что в SQL, второй раз здесь НЕ сортируется,
  // страницы просто конкатенируются, см. loadMoreOperations) и
  // eq_currency_uuid ответа (нужен opsRowHtml — formatEqAmount сравнивает
  // currency_uuid строки именно с ним). opsState — фильтры/выбранная
  // операция/сколько строк показано; сбрасывается заново в refreshOperations()
  // при каждой новой загрузке периода.
  var opsAll = [];
  var opsIncomplete = false;
  var opsEqCurrencyUuid = '';
  var opsState = { q: '', type: 'all', cat: null, wal: null, sel: null, limit: 60 };

  // Пагинация "Списка операций" — по прямому запросу, см. шапку раздела
  // выше. opsLoadParams — {from, to, eq} ТЕКУЩЕГО периода (loadMoreOperations
  // вызывает /operations с ними же плюс курсор — сам period-from/-to к тому
  // моменту мог уже не совпадать с полями шапки, если пользователь успел их
  // поменять, но ещё не нажал "Обновить", см. refreshPeriod). opsHasMore/
  // opsNextCursor* — эхо последнего ответа сервера (has_more/next_cursor_*).
  // opsFetchingMore — идёт ли прямо сейчас догрузка следующей страницы (и
  // защита от повторного запуска, и переключатель текста в хвосте списка,
  // см. renderOpsList). opsLoadToken растёт на каждый refreshOperations() —
  // ответ догрузки, запущенной ДО смены периода/сброса, игнорируется, если
  // токен уже не совпадает (пользователь мог сменить период, пока страница
  // летела по сети).
  var opsLoadParams = null;
  var opsHasMore = false;
  var opsNextCursorDate = '';
  var opsNextCursorUuid = '';
  var opsFetchingMore = false;
  var opsLoadToken = 0;
  var opsScrollObserver = null; // IntersectionObserver на #ops-sentinel, см. wireOpsInfiniteScroll

  function isoDow(d) {
    var w = d.getDay(); // 0=воскресенье..6=суббота
    return w === 0 ? 7 : w; // 1=понедельник..7=воскресенье, см. WEEKDAY_ABBR (Пн..Вс)
  }

  // Одна операция подходит под фильтры opsState — тем же условием, что
  // opsVals() в дизайне (см. Design/.../Отчёты - веб (офлайн).html): тип,
  // категория, кошелёк (по ЛЮБОЙ стороне проводки — from_uuid/to_uuid
  // заполнены для ЛЮБОГО kind, в отличие от category_uuid/wallet_uuid,
  // пустых у transfer, см. reports_repo.hpp), и текст — по комментарию,
  // категории и обоим счетам сразу.
  function opsMatchesFilter(r) {
    var s = opsState;
    if (s.type !== 'all' && r.kind !== s.type) return false;
    if (s.cat && r.category_uuid !== s.cat) return false;
    if (s.wal && r.from_uuid !== s.wal && r.to_uuid !== s.wal) return false;
    var q = s.q.trim().toLowerCase();
    if (q) {
      var hay = (r.comment + ' ' + r.category_name + ' ' + r.from_name + ' ' + r.to_name).toLowerCase();
      if (hay.indexOf(q) < 0) return false;
    }
    return true;
  }

  // Категории/кошельки для чипов — из ВСЕГО загруженного периода (opsAll), а
  // не из уже отфильтрованных строк: иначе, скажем, выбор типа "Доход" на лету
  // убирал бы чипы категорий, которых в доходе не было, и пользователь терял
  // бы точку возврата к "Все статьи". Тот же принцип, что statичный CATS/WAL
  // в дизайне (там список категорий вообще не зависит от текущей выборки).
  function opsDistinctCategories() {
    var seen = {}, list = [];
    opsAll.forEach(function (r) {
      if (!r.category_uuid || seen[r.category_uuid]) return;
      seen[r.category_uuid] = true;
      list.push({ uuid: r.category_uuid, name: r.category_name });
    });
    list.sort(function (a, b) { return a.name.localeCompare(b.name, 'ru'); });
    return list;
  }

  // wallet_uuid/wallet_name — единственный кошелёк expense/income (пусто у
  // transfer); у transfer кошелька ДВА, from_uuid/to_uuid — оба реальные
  // кошельки в этом случае (см. reports_repo.hpp).
  function opsDistinctWallets() {
    var seen = {}, list = [];
    function add(uuid, name) {
      if (!uuid || seen[uuid]) return;
      seen[uuid] = true;
      list.push({ uuid: uuid, name: name });
    }
    opsAll.forEach(function (r) {
      if (r.kind === 'transfer') { add(r.from_uuid, r.from_name); add(r.to_uuid, r.to_name); }
      else { add(r.wallet_uuid, r.wallet_name); }
    });
    list.sort(function (a, b) { return a.name.localeCompare(b.name, 'ru'); });
    return list;
  }

  function opsRowKindColor(kind) {
    return kind === 'expense' ? 'var(--exp)' : kind === 'income' ? 'var(--inc)' : 'var(--ink4)';
  }

  // Иконка строки — категории (см. categoryIconHtml) у expense/income; у
  // transfer иконки нет вовсе (нет категории, см. .sql) — кружок с "⇄"
  // чисто на CSS, без картинки.
  function opsRowIconHtml(r) {
    if (r.kind === 'transfer') return '<span class="ops-row-icon ops-row-icon-transfer">⇄</span>';
    if (r.kind === 'revaluation') return '<span class="ops-row-icon ops-row-icon-transfer">⇅</span>';
    return categoryIconHtml(r.icon_sha256, 'ops-row-icon');
  }

  function opsRowHtml(r) {
    var name = opsRowTitle(r);
    var sub = r.kind === 'transfer' ? (r.from_name + ' → ' + r.to_name)
      : r.kind === 'revaluation' ? 'Переоценка · ' + r.wallet_name
      : (r.category_name + ' · ' + r.wallet_name);
    if (sub === name) sub = ''; // transfer без комментария — не повторять один и тот же "A → B" дважды
    var sign = opsRowSign(r);
    return (
      '<div class="ops-row' + (opsState.sel === r.operation_uuid ? ' selected' : '') +
      '" data-ops-action="select-op" data-value="' + r.operation_uuid + '">' +
      opsRowIconHtml(r) +
      '<div class="ops-row-main">' +
      '<div class="ops-row-name">' + escapeHtml(name) + '</div>' +
      (sub ? '<div class="ops-row-sub">' + escapeHtml(sub) + '</div>' : '') +
      '</div>' +
      '<div class="ops-row-time">' + escapeHtml(r.date.slice(11, 16)) + '</div>' +
      '<div class="ops-row-amount">' +
      '<div style="color:' + opsRowKindColor(r.kind) + '">' + sign + fmtNative(r.amount, r.symbol) + '</div>' +
      '<div class="ops-row-eq">' + formatEqAmount(r.currency_uuid, opsEqCurrencyUuid, r.amount_eq) + '</div>' +
      '</div>' +
      '</div>'
    );
  }

  // "Сегодня"/"Вчера" — по РЕАЛЬНОЙ текущей дате (в отличие от дизайна, где
  // это захардкожено на 2026-07-24, см. TODAY в его коде).
  function opsDayLabel(dayStr) {
    var today = isoDate(new Date());
    var yesterday = isoDate(addDays(new Date(), -1));
    if (dayStr === today) return 'Сегодня';
    if (dayStr === yesterday) return 'Вчера';
    var d = new Date(dayStr + 'T00:00:00');
    return d.getDate() + ' ' + RU_MONTH_GEN[d.getMonth()];
  }

  // Строки уже отсортированы по дате убыв. (сервер, см. .sql) — группировка
  // просто идёт по порядку, без повторной сортировки.
  function opsGroupByDay(rows) {
    var groups = [], byDay = {};
    rows.forEach(function (r) {
      var day = r.date.slice(0, 10);
      if (!byDay[day]) {
        byDay[day] = { day: day, items: [], exp: 0, inc: 0 };
        groups.push(byDay[day]);
      }
      byDay[day].items.push(r);
      var eq = parseFloat(r.amount_eq); // "" (курс не нашёлся) -> NaN, isNaN ниже — тихо пропускает, не 0
      if (!isNaN(eq)) {
        if (r.kind === 'expense') byDay[day].exp += eq;
        else if (r.kind === 'income') byDay[day].inc += eq;
      }
    });
    return groups;
  }

  function opsDayGroupHtml(g) {
    var d = new Date(g.day + 'T00:00:00');
    var totals = '';
    if (g.exp) totals += '<span class="ops-day-exp">−' + fmtEq(g.exp.toFixed(2)) + '</span>';
    if (g.inc) totals += '<span class="ops-day-inc">+' + fmtEq(g.inc.toFixed(2)) + '</span>';
    return (
      '<div class="ops-day">' +
      '<div class="ops-day-head">' +
      '<span class="ops-day-name">' + escapeHtml(opsDayLabel(g.day)) + '</span>' +
      '<span class="ops-day-dow">' + WEEKDAY_ABBR[isoDow(d) - 1] + ', ' + d.getFullYear() + '</span>' +
      '<span class="ops-day-totals">' + totals + '</span>' +
      '</div>' +
      g.items.map(opsRowHtml).join('') +
      '</div>'
    );
  }

  function opsChipHtml(action, uuid, label, active) {
    return (
      '<button type="button" class="ops-chip' + (active ? ' active' : '') + '" data-ops-action="' + action +
      '" data-value="' + (uuid === null ? '' : uuid) + '">' + escapeHtml(label) + '</button>'
    );
  }

  // Раскрыт ли фильтр «Операций» на телефоне (по прямому запросу — "при
  // большом числе категорий фильтр широко уходит, и его не свернуть"). Там
  // он стартует свёрнутым в одну строку-сводку (.ops-filter-summary), по тапу
  // раскрывается панелью: чипы переносятся по строкам, длинный список статей
  // прокручивается внутри своей высоты (style.css, "Фильтр операций на
  // телефоне"). На десктопе не читается: там сводка скрыта, панель видна
  // всегда.
  var opsFiltersOpen = false;

  function opsFilterSummaryText(filteredCount) {
    var s = opsState;
    var parts = [];
    var type = opsTypes().filter(function (t) { return t[0] === s.type; })[0];
    if (type && s.type !== 'all') parts.push(type[1]);
    var cat = s.cat && opsDistinctCategories().filter(function (c) { return c.uuid === s.cat; })[0];
    parts.push(cat ? cat.name : 'Все статьи');
    var wal = s.wal && opsDistinctWallets().filter(function (w) { return w.uuid === s.wal; })[0];
    parts.push(wal ? wal.name : 'Все кошельки');
    return parts.join(' · ') + ' · ' + filteredCount;
  }

  function renderOpsFilters(filteredCount) {
    var el = document.getElementById('ops-filters');
    el.classList.toggle('ops-filters-open', opsFiltersOpen);
    var s = opsState;
    var typeButtons = opsTypes().map(function (t) {
      return (
        '<button type="button" class="ops-seg-btn' + (s.type === t[0] ? ' active' : '') +
        '" data-ops-action="type" data-value="' + t[0] + '">' + escapeHtml(t[1]) + '</button>'
      );
    }).join('');
    var catChips = opsChipHtml('cat', null, 'Все статьи', !s.cat) +
      opsDistinctCategories().map(function (c) { return opsChipHtml('cat', c.uuid, c.name, s.cat === c.uuid); }).join('');
    var walChips = opsChipHtml('wal', null, 'Все кошельки', !s.wal) +
      opsDistinctWallets().map(function (w) { return opsChipHtml('wal', w.uuid, w.name, s.wal === w.uuid); }).join('');

    el.innerHTML =
      '<button type="button" class="ops-filter-summary" data-ops-action="toggle-filters" aria-expanded="' +
      (opsFiltersOpen ? 'true' : 'false') + '">' +
      '<span class="ops-filter-summary-text">' + escapeHtml(opsFilterSummaryText(filteredCount)) + '</span>' +
      '<svg class="currency-picker-arrow" viewBox="0 0 10 6" width="10" height="6" aria-hidden="true">' +
      '<path d="M1 1l4 4 4-4" fill="none" stroke="currentColor" stroke-width="1.5" ' +
      'stroke-linecap="round" stroke-linejoin="round"/></svg>' +
      '</button>' +
      '<div class="ops-filter-panel">' +
      '<div class="ops-toolbar-row">' +
      '<div class="ops-seg-group">' + typeButtons + '</div>' +
      '<button type="button" class="link-btn" data-ops-action="clear">Сбросить</button>' +
      '</div>' +
      '<div class="ops-chip-group">' + catChips + '</div>' +
      '<div class="ops-chip-group ops-chip-group-wal">' + walChips +
      '<span class="ops-count">Найдено ' + filteredCount + '</span>' +
      '</div>' +
      '</div>';
  }

  // Хвост списка — по прямому запросу ("infinite scroll", см. шапку раздела
  // выше): moreLocal>0 — уже ЗАГРУЖЕНО, просто раскрыто меньше (виртуальный
  // рендер, тот же opsState.limit, что и раньше, только без кнопки);
  // opsHasMore — сервер сообщил, что после уже загруженного есть ещё
  // страницы. Пока идёт сетевая догрузка (opsFetchingMore) — текстовый
  // статус вместо сентинела: иначе IntersectionObserver у уже видимого,
  // никуда не девшегося сентинела запустил бы вторую догрузку поверх первой
  // (loadMoreOperations и так защищён флагом, но лишний повторный вызов —
  // не повод не показать пользователю, что список уже грузится).
  function renderOpsList(rows) {
    var el = document.getElementById('ops-list');
    if (!rows.length) {
      el.innerHTML =
        '<p class="wallet-empty">Под фильтры не попала ни одна операция. Снимите часть условий или расширьте период в шапке.</p>';
      observeOpsSentinel();
      return;
    }
    var shown = rows.slice(0, opsState.limit);
    var groups = opsGroupByDay(shown);
    var moreLocal = rows.length > shown.length;
    var tailHtml;
    if (opsFetchingMore) {
      tailHtml = '<div class="ops-list-status">Загрузка ещё…</div>';
    } else if (moreLocal || opsHasMore) {
      tailHtml = '<div class="ops-sentinel" id="ops-sentinel"></div>';
    } else {
      tailHtml = '<div class="ops-list-status">Это все операции периода.</div>';
    }
    el.innerHTML = groups.map(opsDayGroupHtml).join('') + tailHtml;
    observeOpsSentinel();
  }

  function opsTotalsHtml(rows) {
    var exp = 0, inc = 0;
    rows.forEach(function (r) {
      var eq = parseFloat(r.amount_eq);
      if (isNaN(eq)) return;
      if (r.kind === 'expense') exp += eq; else if (r.kind === 'income') inc += eq;
    });
    var net = inc - exp;
    var expCount = rows.filter(function (r) { return r.kind === 'expense'; }).length;
    var prefix = opsIncomplete ? '~ ' : '';
    return (
      '<div class="ops-totals-row"><span>Расход</span><span style="color:var(--exp)">' + prefix + fmtEq(exp.toFixed(2)) + '</span></div>' +
      '<div class="ops-totals-row"><span>Доход</span><span style="color:var(--inc)">' + prefix + fmtEq(inc.toFixed(2)) + '</span></div>' +
      '<div class="ops-totals-row ops-totals-net"><span>Итог</span><span style="color:' + (net >= 0 ? 'var(--inc)' : 'var(--exp)') + '">' +
      prefix + (net < 0 ? '−' : '') + fmtEq(Math.abs(net).toFixed(2)) + '</span></div>' +
      '<div class="ops-totals-row"><span>Средний расход</span><span>' + (expCount ? fmtEq((exp / expCount).toFixed(2)) : '—') + '</span></div>'
    );
  }

  function opsTopCategoriesHtml(rows) {
    var sums = {}, names = {}, icons = {};
    rows.forEach(function (r) {
      if (r.kind !== 'expense' || !r.category_uuid) return;
      var eq = parseFloat(r.amount_eq);
      if (isNaN(eq)) return;
      sums[r.category_uuid] = (sums[r.category_uuid] || 0) + eq;
      names[r.category_uuid] = r.category_name;
      icons[r.category_uuid] = r.icon_sha256;
    });
    var top = Object.keys(sums)
      .map(function (uuid) { return { uuid: uuid, sum: sums[uuid] }; })
      .sort(function (a, b) { return b.sum - a.sum; })
      .slice(0, 5);
    if (!top.length) return '<p class="wallet-empty">Нет расходов в выборке.</p>';
    var maxSum = top[0].sum;
    return top.map(function (t) {
      var pct = Math.round((t.sum / maxSum) * 100);
      return (
        '<div class="ops-top-row" data-ops-action="cat" data-value="' + t.uuid + '">' +
        categoryIconHtml(icons[t.uuid], 'ops-top-icon') +
        '<div class="ops-top-info">' +
        '<div class="ops-top-head"><span class="ops-top-name">' + escapeHtml(names[t.uuid]) +
        '</span><span class="ops-top-sum">' + fmtEq(t.sum.toFixed(2)) + '</span></div>' +
        '<div class="reports-bar"><div class="reports-bar-fill" style="width:' + pct + '%"></div></div>' +
        '</div></div>'
      );
    }).join('');
  }

  function opsSelectedHtml(rows) {
    var sel = opsState.sel ? rows.filter(function (r) { return r.operation_uuid === opsState.sel; })[0] : null;
    if (!sel) return '';
    var name = opsRowTitle(sel);
    var kindLabel = sel.kind === 'expense' ? 'Расход' : sel.kind === 'income' ? 'Доход'
      : sel.kind === 'revaluation' ? 'Переоценка' : 'Перевод';
    var sign = opsRowSign(sel);
    var rows2 = [
      ['Дата', sel.date.slice(8, 10) + ' ' + RU_MONTH_GEN[parseInt(sel.date.slice(5, 7), 10) - 1] + ' ' +
        sel.date.slice(0, 4) + ', ' + sel.date.slice(11, 16)],
      ['Списано с', sel.from_name],
      ['Зачислено на', sel.to_name],
      ['Сумма проводки', groupThousands(sel.amount) + ' ' + sel.symbol],
    ];
    if (sel.comment) rows2.push(['Комментарий', sel.comment]);
    var note = sel.kind === 'transfer'
      ? 'Перевод хранится двумя связанными проводками — по одной на каждый кошелёк, если валюты кошельков различались.'
      : sel.kind === 'revaluation'
        ? 'Переоценка меняет оценку актива и не считается ни доходом, ни расходом. Одна проводка: ' +
          sel.from_name + ' → ' + sel.to_name + '.'
        : 'Одна проводка: ' + sel.from_name + ' → ' + sel.to_name + '.';
    return (
      '<section class="report-section ops-selected">' +
      '<div class="ops-selected-head">' + opsRowIconHtml(sel) +
      '<div><div class="ops-selected-name">' + escapeHtml(name) + '</div>' +
      '<div class="ops-selected-kind">' + kindLabel + '</div></div></div>' +
      '<div class="ops-selected-amount" style="color:' + opsRowKindColor(sel.kind) + '">' + sign + fmtNative(sel.amount, sel.symbol) + '</div>' +
      rows2.map(function (r) {
        return '<div class="ops-selected-row"><span>' + escapeHtml(r[0]) + '</span><span>' + escapeHtml(r[1]) + '</span></div>';
      }).join('') +
      '<div class="ops-selected-note">' + escapeHtml(note) + '</div>' +
      '</section>'
    );
  }

  function renderOpsSidebar(rows) {
    var el = document.getElementById('ops-sidebar');
    el.innerHTML =
      '<section class="report-section"><h2>Итого по фильтру</h2>' + opsTotalsHtml(rows) + '</section>' +
      '<section class="report-section"><h2>Статьи в выборке</h2><div class="ops-top-list">' +
      opsTopCategoriesHtml(rows) + '</div></section>' +
      opsSelectedHtml(rows);
  }

  // Пересчитать/перерисовать всё вью 'ops' из opsAll+opsState — вызывается
  // при ЛЮБОМ изменении фильтров/выбора, без похода в сеть (см. шапку
  // раздела). Сам #ops-search (поле поиска) сюда не входит и не
  // перерисовывается — иначе на каждое нажатие клавиши терялся бы фокус
  // курсора; его 'input'-обработчик (см. wireOpsEvents) сам меняет только
  // opsState.q и зовёт эту функцию.
  function renderOpsBody() {
    if (!document.getElementById('ops-list')) return; // вкладка 'ops' ещё не построена (renderReports() строит все вью сразу, но защититься дешевле, чем предполагать порядок)
    var rows = opsAll.filter(opsMatchesFilter);
    renderOpsFilters(rows.length);
    renderOpsList(rows);
    renderOpsSidebar(rows);
  }

  // Один IntersectionObserver на всё время жизни SPA (тот же приём, что
  // curChartDragWired у графика курса) — #ops-sentinel каждый раз новый
  // DOM-узел (renderOpsList пересоздаёт его через innerHTML), поэтому
  // re-observe нужен после КАЖДОЙ перерисовки списка, а не создание нового
  // Observer'а — см. observeOpsSentinel, вызывается из renderOpsList.
  function wireOpsInfiniteScroll() {
    if (typeof IntersectionObserver === 'undefined') return; // старый браузер — просто без бесконечной подгрузки, конец списка молча не пишется как "это все операции"
    opsScrollObserver = new IntersectionObserver(function (entries) {
      if (entries[0].isIntersecting) onOpsScrollNearEnd();
    });
  }

  // disconnect() ПЕРЕД повторным observe() — старый #ops-sentinel уже вышел
  // из DOM (innerHTML пересоздал список), но без явного disconnect Observer
  // продолжал бы держать его в памяти лишним висячим наблюдением.
  function observeOpsSentinel() {
    if (!opsScrollObserver) return;
    opsScrollObserver.disconnect();
    var sentinel = document.getElementById('ops-sentinel');
    if (sentinel) opsScrollObserver.observe(sentinel);
  }

  // Сентинел внизу списка попал во вьюпорт — сначала раскрыть уже
  // ЗАГРУЖЕННОЕ (дёшево, без сети), и только когда локальный запас
  // исчерпан — идти за следующей страницей на сервер.
  function onOpsScrollNearEnd() {
    if (opsFetchingMore) return;
    var filteredCount = opsAll.filter(opsMatchesFilter).length;
    if (opsState.limit < filteredCount) {
      opsState.limit += 60;
      renderOpsBody();
      return;
    }
    if (opsHasMore) loadMoreOperations();
  }

  // Следующая страница /api/reports/operations — тем же курсором, что вернул
  // предыдущий ответ (opsNextCursorDate/opsNextCursorUuid). opsLoadToken —
  // если пользователь успел сменить период/нажать "Обновить", пока страница
  // летела по сети (refreshOperations уже увеличил токен и начал заново с
  // opsAll = []), этот ответ приехал уже ни к чему не относящимся — не
  // применяем его поверх нового состояния.
  function loadMoreOperations() {
    if (!opsLoadParams || opsFetchingMore || !opsHasMore) return;
    opsFetchingMore = true;
    var token = opsLoadToken;
    renderOpsBody(); // сразу показать "Загрузка ещё…" в хвосте, не дожидаясь сети
    fetchReport('operations', {
      from: opsLoadParams.from, to: opsLoadParams.to, eq_currency: opsLoadParams.eq,
      limit: 1000, cursor_date: opsNextCursorDate, cursor_uuid: opsNextCursorUuid,
    })
      .then(function (data) {
        if (token !== opsLoadToken) return;
        opsFetchingMore = false;
        if (!data) { renderOpsBody(); return; } // 401 — renderLogin() уже сработал внутри fetchReport
        opsAll = opsAll.concat(data.operations);
        if (data.incomplete) opsIncomplete = true;
        opsHasMore = data.has_more;
        opsNextCursorDate = data.has_more ? data.next_cursor_date : '';
        opsNextCursorUuid = data.has_more ? data.next_cursor_uuid : '';
        opsState.limit += 60; // сразу раскрыть хотя бы часть только что подгруженной страницы
        renderOpsBody();
      })
      .catch(function () {
        if (token !== opsLoadToken) return;
        opsFetchingMore = false;
        // Не рушим уже показанный список ошибкой одной догрузки — просто
        // убираем "Загрузка…"; сентинел вернётся, следующий доскролл
        // попробует снова.
        renderOpsBody();
      });
  }

  // Один делегированный обработчик на весь вид — чипы/кнопки/строки
  // перестраиваются на каждый renderOpsBody(), навешивать заново слушатели
  // на каждый элемент после каждой перерисовки было бы и дороже, и хрупче.
  function wireOpsEvents() {
    document.getElementById('view-ops').addEventListener('click', function (ev) {
      var el = ev.target.closest('[data-ops-action]');
      if (!el) return;
      var action = el.getAttribute('data-ops-action');
      var value = el.getAttribute('data-value');
      // Выбор статьи/кошелька на телефоне сворачивает фильтр обратно — как
      // фильтр периода после «Обновить»: раскрытая панель закрывает список.
      // Тип — переключатель из четырёх-пяти кнопок, его щёлкают подряд — не сворачиваем.
      if (action === 'toggle-filters') { opsFiltersOpen = !opsFiltersOpen; }
      else if (action === 'type') { opsState.type = value; opsState.limit = 60; }
      else if (action === 'cat') { opsState.cat = value || null; opsState.limit = 60; opsFiltersOpen = false; }
      else if (action === 'wal') { opsState.wal = value || null; opsState.limit = 60; opsFiltersOpen = false; }
      else if (action === 'clear') { opsState.q = ''; opsState.type = 'all'; opsState.cat = null; opsState.wal = null; opsState.limit = 60; document.getElementById('ops-search').value = ''; }
      else if (action === 'select-op') { opsState.sel = opsState.sel === value ? null : value; }
      else return;
      renderOpsBody();
    });
    document.getElementById('ops-search').addEventListener('input', function (ev) {
      opsState.q = ev.target.value;
      opsState.limit = 60;
      renderOpsBody();
    });
  }

  // presetCat — категория, с которой должен открыться список (см.
  // goToOperationsForCategory); во всех остальных вызовах (шапка "Отчётов",
  // "Обновить") аргумент не передаётся, и фильтр по категории, как раньше,
  // сбрасывается вместе со всем остальным opsState.
  function refreshOperations(presetCat, presetWal) {
    var listEl = document.getElementById('ops-list');
    if (!listEl) return;
    listEl.innerHTML = '<p class="sub">Загрузка…</p>';
    document.getElementById('ops-filters').innerHTML = '';
    document.getElementById('ops-sidebar').innerHTML = '';
    // Новый период — прежние фильтры/выбор к нему не привязаны (выбранная
    // операция вообще могла из него выпасть) — тот же принцип, что и сброс
    // opsLimit в дизайне при смене фильтра, только здесь ещё шире. presetWal —
    // клик по строке кошелька на "Кошельках и остатках" (см.
    // goToOperationsForWallet), тот же приём "детализации", что и presetCat.
    opsState = { q: '', type: 'all', cat: presetCat || null, wal: presetWal || null, sel: null, limit: 60 };
    document.getElementById('ops-search').value = '';

    var eq = eqCurrencyValue();
    var from = document.getElementById('period-from').value + 'T00:00:00';
    var to = document.getElementById('period-to').value + 'T23:59:59';
    // Новый период/сброс — предыдущая незавершённая догрузка (loadMoreOperations),
    // если она была в полёте, больше не актуальна: её ответ, когда бы он ни
    // пришёл, сравнит свой захваченный token с НОВЫМ opsLoadToken и не пройдёт.
    opsLoadParams = { from: from, to: to, eq: eq };
    opsHasMore = false;
    opsNextCursorDate = '';
    opsNextCursorUuid = '';
    opsFetchingMore = false;
    var token = ++opsLoadToken;

    // Первая страница — не более 1000 операций (по прямому запросу, "по
    // умолчанию 1000, если 20 лет — не тащить всё"), без курсора; остальные —
    // по доскроллу до низа списка (см. loadMoreOperations/onOpsScrollNearEnd).
    fetchReport('operations', { from: from, to: to, eq_currency: eq, limit: 1000 })
      .then(function (data) {
        if (token !== opsLoadToken) return; // период/фильтр снова сменили, пока эта страница летела
        if (!data) return;
        opsAll = data.operations;
        opsIncomplete = data.incomplete;
        opsEqCurrencyUuid = data.eq_currency_uuid;
        opsHasMore = data.has_more;
        opsNextCursorDate = data.has_more ? data.next_cursor_date : '';
        opsNextCursorUuid = data.has_more ? data.next_cursor_uuid : '';
        renderOpsBody();
      })
      .catch(function (err) {
        if (token !== opsLoadToken) return;
        listEl.innerHTML = reportsErrorHtml('Не удалось загрузить список операций: ' + err.message);
      });
  }

  // "Структура расходов" (servers/Design/.../Отчёты - веб.dc.html, экран
  // "структура") — GET /api/reports/expense-structure (wallet-api,
  // reports_repo.cpp::expense_structure_for_period). В отличие от дизайна —
  // без переключателя "Категории/Группы": в реальной схеме БД (account) нет
  // понятия "группа категории", категории плоские (см. чат) — и без
  // treemap-карты, простой список с полосой доли (та же экономия усилий,
  // что и остальной этот экран: без внешних библиотек, без отдельной
  // дизайн-системы Organic из макета).

  // Период сравнения ВЫЧИСЛЯЕТ фронтенд (сервису отдаются уже готовые
  // cmp_from/cmp_to, см. openapi.yaml) — "предыдущий период" и "год назад"
  // из дизайна. from/to — как раз "yyyy-mm-dd" из <input type="date">.
  function computeCmpRange(mode, fromDateStr, toDateStr) {
    if (mode === 'none') return null;
    var from = new Date(fromDateStr + 'T00:00:00');
    var to = new Date(toDateStr + 'T00:00:00');
    if (mode === 'year') {
      var yf = new Date(from.getTime());
      yf.setFullYear(yf.getFullYear() - 1);
      var yt = new Date(to.getTime());
      yt.setFullYear(yt.getFullYear() - 1);
      return { from: yf, to: yt };
    }
    // 'prev' — тот же по длине период, вплотную ПЕРЕД from (граница from
    // включительна, поэтому "день перед from", а не сам from).
    var durationMs = to.getTime() - from.getTime();
    var dayMs = 24 * 60 * 60 * 1000;
    var cmpTo = new Date(from.getTime() - dayMs);
    var cmpFrom = new Date(cmpTo.getTime() - durationMs);
    return { from: cmpFrom, to: cmpTo };
  }

  // ЛОКАЛЬНЫЕ компоненты даты (getFullYear/getMonth/getDate), НЕ toISOString()
  // (по прямому запросу, 2026-09-12 — расследование "Обзор... рисует
  // большое количество сентябрей"): весь остальной код модуля строит Date
  // из локальной полуночи (new Date(str + 'T00:00:00'), БЕЗ 'Z' — см.
  // shiftMonth/lastDayOfMonth/isoWeekMonday/shiftYear/addDays и далее), а
  // toISOString() отдаёт UTC. В любом часовом поясе ВОСТОЧНЕЕ UTC (Европа,
  // Москва и т.п. — положительный оффсет) локальная полночь пересчитывается
  // в UTC как "вчера вечером", и .slice(0,10) молча откатывает дату на
  // день назад — старый isoDate(d) был НЕ функцией "формат ISO", а функцией
  // "минус один день почти везде, кроме UTC+0/западных поясов".
  //
  // В одиночном вызове (shiftMonth(x, -1) и т.п.) это давало на день не ту
  // дату — заметно, но терпимо. В buildBuckets/nextBucketStart, где
  // shiftMonth зовётся ПО КРУГУ (выход одного вызова — вход следующего),
  // ошибка не гасла, а НАКАПЛИВАЛАСЬ до неподвижной точки: shiftMonth,
  // однажды докатившись до "YYYY-MM-30" (последний день месяца ДО
  // задуманного), на каждой следующей итерации снова возвращал ТУ ЖЕ
  // дату — bucketStart застревал на одном и том же месяце (в это лето —
  // сентябрь) до guard-предохранителя (5000 итераций), рисуя тысячи
  // одинаковых столбцов "сен" вместо честной последовательности месяцев.
  //
  // Фикс — формат из ЛОКАЛЬНЫХ полей Date, тот же тайм-зон, в котором d была
  // построена везде в этом модуле: isoDate(new Date(str+'T00:00:00')) снова
  // честная тождественная функция для ЛЮБОГО часового пояса, не только UTC.
  function isoDate(d) {
    var m = d.getMonth() + 1;
    var day = d.getDate();
    return d.getFullYear() + '-' + (m < 10 ? '0' : '') + m + '-' + (day < 10 ? '0' : '') + day;
  }

  // --- Группировка графиков по бакетам (день/неделя/месяц/год) -----------
  // По прямому запросу (2026-09-11): "Обзор" (Расход по месяцам), "Динамика"
  // (бывш. "Динамика по месяцам") и "Категории во времени" раньше каждый жил
  // на своём фиксированном окне (12/24 месяца), НЕЗАВИСИМО от выбранного
  // period-from/-to — теперь все три строятся из ОДНОГО и того же реального
  // интервала фильтра, разбитого на бакеты выбранной длины (#period-group,
  // groupByValue ниже). НИ ОДНОЙ новой SQL-функции — f_income_expense_by_month
  // умеет группировать только по месяцу, поэтому "Обзор"/"Динамика" тоже
  // переведены на клиентскую агрегацию плоского operations_for_period, тем же
  // приёмом, что уже был у "Категорий" (см. buildCatsFromOperations ниже).

  function groupByValue() {
    var el = document.getElementById('period-group');
    return (el && el.value) || 'month';
  }

  // Понедельник ISO-недели, содержащей dateStr — тот же локально-временной
  // приём (new Date(str+'T00:00:00'), без 'Z'), что и everywhere в этом
  // модуле (shiftMonth/lastDayOfMonth) — не смешивать с UTC-разбором.
  function isoWeekMonday(dateStr) {
    var d = new Date(dateStr + 'T00:00:00');
    var dow = (d.getDay() + 6) % 7; // Пн=0..Вс=6 (getDay() отдаёт Вс=0..Сб=6)
    d.setDate(d.getDate() - dow);
    return isoDate(d);
  }

  // Начало бакета, которому принадлежит dateStr, и начало СЛЕДУЮЩЕГО бакета
  // той же группировки — пара примитивов, из которых строится всё остальное
  // ниже (buildBuckets/bucketEnd).
  function shiftYear(dateStr, delta) {
    var d = new Date(dateStr + 'T00:00:00');
    d.setFullYear(d.getFullYear() + delta);
    return isoDate(d);
  }

  function bucketStart(dateStr, groupBy) {
    if (groupBy === 'day') return dateStr;
    if (groupBy === 'week') return isoWeekMonday(dateStr);
    if (groupBy === 'year') return dateStr.slice(0, 4) + '-01-01';
    return dateStr.slice(0, 7) + '-01'; // 'month'
  }

  function nextBucketStart(bucketStartStr, groupBy) {
    if (groupBy === 'day') return isoDate(addDays(new Date(bucketStartStr + 'T00:00:00'), 1));
    if (groupBy === 'week') return isoDate(addDays(new Date(bucketStartStr + 'T00:00:00'), 7));
    if (groupBy === 'year') return shiftYear(bucketStartStr, 1);
    return shiftMonth(bucketStartStr, 1);
  }

  function bucketEnd(bucketStartStr, groupBy) {
    return isoDate(addDays(new Date(nextBucketStart(bucketStartStr, groupBy) + 'T00:00:00'), -1));
  }

  // Начало ПРЕДЫДУЩЕГО бакета той же группировки — "К пред. периоду"
  // на "Динамике" (renderDynamicsSelected) и разбор соседнего бакета по
  // категориям (selectDynamicsMonth), тот же смысл, что раньше был у
  // shiftMonth(-1), но для любой группировки, не только месяца.
  function prevBucketStart(bucketStartStr, groupBy) {
    if (groupBy === 'day') return isoDate(addDays(new Date(bucketStartStr + 'T00:00:00'), -1));
    if (groupBy === 'week') return isoDate(addDays(new Date(bucketStartStr + 'T00:00:00'), -7));
    if (groupBy === 'year') return shiftYear(bucketStartStr, -1);
    return shiftMonth(bucketStartStr, -1);
  }

  // Список начал бакетов, календарно покрывающих [fromIso, toIso] целиком —
  // первый/последний бакет может частично выходить за границы интервала
  // (тот же смысл, что раньше был у частичного крайнего месяца окна
  // "Категорий"/"Динамики") — данные в них всё равно уже отрезаны сервером
  // по from/to, лишнего не покажет. guard — предохранитель от зависания на
  // испорченных датах, реальные окна на 1-2 порядка короче.
  function buildBuckets(fromIso, toIso, groupBy) {
    var buckets = [];
    var cur = bucketStart(fromIso, groupBy);
    var guard = 0;
    while (cur <= toIso && guard < 5000) {
      buckets.push(cur);
      cur = nextBucketStart(cur, groupBy);
      guard++;
    }
    return buckets;
  }

  // Индекс первого бакета, относящегося уже к "текущему" периоду (не к
  // периоду сравнения) — граница проходит вплотную ПЕРЕД curFromIso (см.
  // computeCmpRange('prev', ...) выше), поэтому первый бакет с
  // start >= curFromIso и есть первый "живой" (не приглушённый) столбец.
  function bucketSplitIndex(buckets, curFromIso) {
    for (var i = 0; i < buckets.length; i++) {
      if (buckets[i] >= curFromIso) return i;
    }
    return buckets.length;
  }

  // Короткая подпись бакета под столбцом графика — месяц как и раньше
  // (MONTH_ABBR + год на январе), день/неделя — "дд.мм" (компактно: год
  // почти никогда не влезает рядом с полосой из полусотни/трёх сотен подписей).
  function bucketAxisLabel(bucketStartStr, groupBy) {
    if (groupBy === 'year') return bucketStartStr.slice(0, 4);
    if (groupBy === 'month') {
      var mn = parseInt(bucketStartStr.slice(5, 7), 10) - 1;
      var yr = bucketStartStr.slice(2, 4);
      return MONTH_ABBR[mn] + (mn === 0 ? " '" + yr : '');
    }
    return bucketStartStr.slice(8, 10) + '.' + bucketStartStr.slice(5, 7);
  }

  function ruShortDate(iso) {
    return iso.slice(8, 10) + '.' + iso.slice(5, 7) + '.' + iso.slice(0, 4);
  }

  // Полная подпись бакета для хинта-крестика (wireMonthlyChartCrosshair) —
  // месяц целиком с годом, как и раньше; неделя — диапазон "с ... по ...";
  // день — число + месяц в родительном падеже + год (тот же RU_MONTH_GEN,
  // что и у дат операций в "Списке операций", см. opsDayLabel). RU_MONTH_FULL/
  // RU_MONTH_GEN — var'ы, объявленные ниже по файлу, но заполняются ДО
  // первого реального вызова этой функции (весь верхнеуровневый код модуля
  // отрабатывает целиком при загрузке страницы, раньше первого рендера).
  function bucketTooltipTitle(bucketStartStr, groupBy) {
    if (groupBy === 'year') return bucketStartStr.slice(0, 4) + ' год';
    if (groupBy === 'month') {
      var mn = parseInt(bucketStartStr.slice(5, 7), 10) - 1;
      return RU_MONTH_FULL[mn] + ' ' + bucketStartStr.slice(0, 4);
    }
    if (groupBy === 'week') {
      return ruShortDate(bucketStartStr) + ' – ' + ruShortDate(bucketEnd(bucketStartStr, groupBy));
    }
    var d = parseInt(bucketStartStr.slice(8, 10), 10);
    var mn2 = parseInt(bucketStartStr.slice(5, 7), 10) - 1;
    return d + ' ' + RU_MONTH_GEN[mn2] + ' ' + bucketStartStr.slice(0, 4);
  }

  // Грамматические формы единицы группировки — дательный мн.ч. ("Расход по
  // месяцам/неделям/дням"), винительный ("В среднем в месяц/неделю/день"),
  // родительный ("Максимум месяца/недели/дня") — три места, где раньше было
  // зашито слово "месяц" в нужном падеже буквально в разметке.
  var GROUP_UNIT = {
    day: { dat_pl: 'дням', acc: 'день', gen: 'дня' },
    week: { dat_pl: 'неделям', acc: 'неделю', gen: 'недели' },
    month: { dat_pl: 'месяцам', acc: 'месяц', gen: 'месяца' },
    year: { dat_pl: 'годам', acc: 'год', gen: 'года' },
  };

  // Сумма расхода/дохода по бакетам — общий приём для "Обзора" и "Динамики"
  // (обе теперь строятся из плоского operations_for_period, а не из
  // f_income_expense_by_month — та не умеет группировать иначе, чем по
  // месяцу). rows — тот же amount_eq/date/kind, что и в
  // buildCatsFromOperations ниже (тот же эндпоинт и форма строки).
  function sumIncomeExpenseByBucket(rows, buckets, groupBy) {
    var idxByStart = {};
    buckets.forEach(function (b, i) { idxByStart[b] = i; });
    var expense = buckets.map(function () { return 0; });
    var income = buckets.map(function () { return 0; });
    rows.forEach(function (r) {
      var eq = parseFloat(r.amount_eq);
      if (isNaN(eq)) return; // курс не нашёлся — та же тихая пропажа строки, что и в buildCatsFromOperations
      var idx = idxByStart[bucketStart(r.date.slice(0, 10), groupBy)];
      if (idx === undefined) return; // теоретически невозможно (сервер уже отрезал по from/to), но не роняем агрегацию
      if (r.kind === 'expense') expense[idx] += eq;
      else if (r.kind === 'income') income[idx] += eq;
    });
    return { expense: expense, income: income };
  }

  // Общее окно "текущий выбранный период + такой же по длине период ДО
  // него" — по прямому запросу (2026-09-11): "Динамика" и "Категории во
  // времени" раньше сравнивали с фиксированными 12 месяцами ДО текущих 12,
  // теперь — с периодом ТОЙ ЖЕ длины, что и сам выбранный интервал (тот же
  // computeCmpRange('prev', ...), что уже используют "Структура"/"Обзор").
  function reportsWindowWithComparison(fromStr, toStr) {
    var cmp = computeCmpRange('prev', fromStr, toStr);
    return { prevFrom: isoDate(cmp.from), prevTo: isoDate(cmp.to), curFrom: fromStr, curTo: toStr };
  }

  // amount_eq категории — НЕ через formatEqAmount(): там разметка "≈"
  // держится на currency_uuid ОДНОЙ строки против eq_currency_uuid ответа, а
  // здесь строка — это уже СУММА (возможно) нескольких валют кошелька за
  // категорию (см. reports_repo.hpp, expense_by_category_for_period) —
  // отдельного currency_uuid у неё просто нет. "~" остаётся — так же, как и
  // везде, означает "курса не нашлось" (пустая строка на этом поле, не
  // JSON null — см. db.cpp, "SQL NULL -> \"\"").
  function formatStructureAmount(amountEq) {
    if (amountEq === '') return '<span class="eq-missing">~</span>';
    return fmtEq(amountEq);
  }

  function pctText(pct) {
    return pct === null || pct === undefined ? '—' : escapeHtml(pct) + '%';
  }

  function ppDeltaHtml(pp) {
    if (pp === null || pp === undefined) return '—';
    var v = parseFloat(pp);
    var cls = v > 0 ? 'delta-up' : v < 0 ? 'delta-down' : '';
    var sign = v > 0 ? '+' : '';
    return '<span class="' + cls + '">' + sign + escapeHtml(pp) + ' п.п.</span>';
  }

  // "Карта расходов" (treemap) — Design/.../Отчёты - веб.dc.html, панель
  // слева на экране "структура" (strTiles). Дизайн подгонял прямоугольники
  // руками под 17 придуманных категорий; здесь настоящий squarified-
  // алгоритм (Bruls/Huizing/van Wijk, 1999) — тот же принцип, что и в d3/
  // большинстве библиотек treemap: строит ряды плиток так, чтобы минимизировать
  // худшее соотношение сторон в ряду, а не просто нарезает полосы по величине.
  // Работает под ЛЮБОЕ число категорий и реальную ширину контейнера — не
  // квадратные проценты, а настоящие px (см. layoutTreemap ниже, зачем).

  // Палитра — 12 цветов PALS.Терракота из дизайна (тот же файл), чтобы
  // плитки выглядели так же, как в макете. Присваивается по порядковому
  // номеру категории в отсортированном (desc по сумме) списке —
  // детерминированно, но не привязано к КОНКРЕТНОЙ категории (в реальных
  // данных их может быть сколько угодно, в отличие от 12 придуманных в
  // макете; при >12 категориях цвета просто повторяются).
  var TREEMAP_PALETTE = [
    '#c67139', '#8c491a', '#dd9257', '#a1552a', '#e8b483', '#7a8a5e',
    '#9fae7f', '#5f6e47', '#c9a06f', '#b07a4a', '#8a6b4e', '#d8c3a0',
  ];

  function treemapTileColor(index) {
    return TREEMAP_PALETTE[index % TREEMAP_PALETTE.length];
  }

  // Хинт (title) для любой "безмолвной" области доли категории — плитки
  // карты расходов и сегмента мини-"Структуры" на "Обзоре": обе рисуют
  // только цвет (плитка — ещё и подписи, если хватает места, сегмент —
  // вовсе ничего), сумму и точный процент видно лишь при наведении.
  function structureAreaHintTitle(c) {
    return c.account_name + ' — ' + fmtEq(c.amount_eq) +
      (c.pct !== null && c.pct !== undefined ? ' (' + c.pct + '%)' : '');
  }

  // Относительная яркость (ITU-R BT.601) — палитра выше вперемешку тёмная
  // (#8c491a) и бледная (#d8c3a0, #e8b483): один on-color на все плитки,
  // как в дизайне, дал бы нечитаемый текст на светлых. Порог 0.6 — эмпирика,
  // не стандарт (формального WCAG-расчёта контраста здесь нет).
  function isDarkColor(hex) {
    var r = parseInt(hex.slice(1, 3), 16);
    var g = parseInt(hex.slice(3, 5), 16);
    var b = parseInt(hex.slice(5, 7), 16);
    return (0.299 * r + 0.587 * g + 0.114 * b) / 255 < 0.6;
  }

  // "1 категория / 2 категории / 5 категорий" — стандартные русские формы
  // множественного числа по остатку от 10/100.
  function pluralRu(n, forms) {
    var mod10 = n % 10;
    var mod100 = n % 100;
    if (mod10 === 1 && mod100 !== 11) return forms[0];
    if (mod10 >= 2 && mod10 <= 4 && (mod100 < 10 || mod100 >= 20)) return forms[1];
    return forms[2];
  }

  // Итеративная версия squarify — на каждом шаге откусывает от прямоугольника
  // (x,y,w,h) одну "строку" плиток вдоль его КОРОТКОЙ стороны (side), набирая
  // в неё элементы по порядку, пока добавление очередного не ухудшает худшее
  // соотношение сторон в строке (worstRatio) — тогда строка закрывается,
  // выкладывается, и алгоритм повторяется для оставшегося прямоугольника.
  // values — площади ещё не переведены: масштаб (w*h)/total переводит суммы
  // категорий в px² так, чтобы плитки заполнили контейнер БЕЗ зазоров.
  function squarifyTreemap(values, w, h) {
    var total = 0;
    for (var i = 0; i < values.length; i++) total += values[i];
    if (total <= 0 || w <= 0 || h <= 0) return [];
    var scale = (w * h) / total;
    var items = values.map(function (v, idx) { return { index: idx, area: v * scale }; });

    function worstRatio(areas, side) {
      var sum = 0, max = areas[0], min = areas[0];
      areas.forEach(function (a) {
        sum += a;
        if (a > max) max = a;
        if (a < min) min = a;
      });
      var sideSq = side * side;
      return Math.max((sideSq * max) / (sum * sum), (sum * sum) / (sideSq * min));
    }

    var out = [];
    var x = 0, y = 0; // левый верхний угол ЕЩЁ НЕ занятого остатка контейнера
    var remaining = items;
    while (remaining.length) {
      var side = Math.min(w, h);
      var row = [remaining[0]];
      var rowAreas = [remaining[0].area];
      var k = 1;
      while (k < remaining.length) {
        var candidateAreas = rowAreas.concat([remaining[k].area]);
        if (worstRatio(candidateAreas, side) <= worstRatio(rowAreas, side)) {
          row.push(remaining[k]);
          rowAreas = candidateAreas;
          k++;
        } else break;
      }
      var rowSum = 0;
      rowAreas.forEach(function (a) { rowSum += a; });

      if (w >= h) {
        // Широкий остаток — строка ложится ВЕРТИКАЛЬНОЙ полосой слева, во
        // всю текущую высоту h; плитки внутри неё — друг под другом.
        var rowW = rowSum / h;
        var cy = y;
        row.forEach(function (it) {
          var itemH = it.area / rowW;
          out.push({ index: it.index, x: x, y: cy, w: rowW, h: itemH });
          cy += itemH;
        });
        x += rowW;
        w -= rowW;
      } else {
        // Высокий остаток — строка ложится ГОРИЗОНТАЛЬНОЙ полосой сверху,
        // во всю текущую ширину w; плитки внутри неё — друг за другом.
        var rowH = rowSum / w;
        var cx = x;
        row.forEach(function (it) {
          var itemW = it.area / rowH;
          out.push({ index: it.index, x: cx, y: y, w: itemW, h: rowH });
          cx += itemW;
        });
        y += rowH;
        h -= rowH;
      }
      remaining = remaining.slice(row.length);
    }
    return out;
  }

  // Высота карты — переменная, её выставляет treemapHeight() инлайн-стилем
  // перед каждой раскладкой. Нижняя граница — min-height из style.css
  // (.treemap-container: 380px, на телефоне 300px) — читается из computed
  // style, чтобы граница жила в ОДНОМ месте: раньше JS считал плитки на
  // фиксированные 380px, а CSS на телефоне давал контейнеру 300px, и нижний
  // ряд плиток обрезался. Fallback — когда стилей нет (jsdom-харнесс).
  var TREEMAP_FALLBACK_MIN_HEIGHT = 380;
  // Ширина, на которой минимальной высоты "хватает": уже неё карта растёт
  // в высоту обратно пропорционально ширине — площадь плиток сохраняется, и
  // при сужении окна плитки уходят вниз, а не сплющиваются в столбики.
  var TREEMAP_REF_WIDTH = 560;
  // Потолок — 2 минимальные высоты: длинный список категорий справа не
  // должен растягивать карту на несколько экранов.
  var TREEMAP_MAX_HEIGHT_FACTOR = 2;

  // Две причины расти выше минимума, берётся бо́льшая:
  //  1) узкий контейнер — площадь (см. TREEMAP_REF_WIDTH);
  //  2) двухколоночная раскладка — колонка "Категории" справа выше карты,
  //     и под картой оставалась пустота: тянем карту до низа соседней
  //     колонки. В одну колонку (<900px, см. .structure-grid) соседняя секция
  //     стоит НИЖЕ — её высота карте не указ (сравниваем offsetTop, а не
  //     дублируем брейкпоинт из CSS).
  function treemapHeight(el, w) {
    var minH = parseFloat(window.getComputedStyle(el).minHeight) || TREEMAP_FALLBACK_MIN_HEIGHT;
    var h = minH * Math.max(1, TREEMAP_REF_WIDTH / w);
    var section = el.closest('.report-section');
    var neighbour = section && section.nextElementSibling;
    if (neighbour && neighbour.offsetTop === section.offsetTop) {
      // Заголовок и подпись под картой — то, что секция добавляет к карте.
      var chrome = section.offsetHeight - el.offsetHeight;
      h = Math.max(h, neighbour.offsetHeight - chrome);
    }
    return Math.round(Math.min(minH * TREEMAP_MAX_HEIGHT_FACTOR, Math.max(minH, h)));
  }

  // Перерисовка карты на ресайз окна и сворачивание сайдбара. Раньше карта
  // строилась по ширине один раз, и при сужении правая часть плиток уезжала
  // под колонку "Категории" (обрезалась overflow:hidden). Реагируем ТОЛЬКО на
  // смену ширины: высоту контейнеру выставляем мы сами, и без этой проверки
  // observer зациклился бы на собственной перерисовке. Ширина 0 — вкладку
  // скрыли (display:none), её покажет switchReportsView. Observer вешается
  // один раз на элемент: renderReports пересоздаёт разметку — новый элемент
  // получит свой, старый уйдёт вместе с DOM-узлом.
  function observeTreemapWidth(el) {
    if (el._treemapObserver || typeof ResizeObserver === 'undefined') return;
    el._treemapObserver = new ResizeObserver(function () {
      var w = el.clientWidth;
      if (!w || w === el._treemapW) return;
      renderTreemapIfVisible();
    });
    el._treemapObserver.observe(el);
  }

  // Кэш последнего ответа /api/reports/expense-structure — нужен, чтобы
  // перерисовать карту РЕАЛЬНОЙ шириной контейнера в момент, когда вкладка
  // "Структура" становится видимой (см. renderTreemapIfVisible ниже): пока
  // #view-struct скрыт атрибутом hidden (display:none), el.clientWidth равен
  // 0 — построить по нему карту нельзя, а без кэша пришлось бы гонять сеть
  // заново при каждом переключении вкладки.
  var lastStructureData = null;

  function renderTreemap(categories) {
    var el = document.getElementById('structure-treemap');
    var noteEl = document.getElementById('structure-treemap-note');
    if (!el) return; // вкладка "Структура" ни разу не открывалась в этой сессии

    // Плиткой можно нарисовать только категорию с ИЗВЕСTНОЙ и положительной
    // суммой ЭТОГО периода: amount_eq "" — курса не нашлось (см.
    // reports_repo.hpp), amount_eq "0" — категория, которая была только в
    // периоде сравнения (см. StructureResult) — площадь для неё либо
    // неизвестна, либо буквально ноль, плитку не построить.
    var sized = categories.filter(function (c) {
      return c.amount_eq !== '' && parseFloat(c.amount_eq) > 0;
    });
    var skipped = categories.length - sized.length;
    noteEl.textContent = skipped > 0
      ? skipped + ' ' + pluralRu(skipped, ['категория', 'категории', 'категорий']) +
        ' без известной суммы за период не показан' + (skipped === 1 ? 'а' : 'ы') + ' на карте'
      : '';

    if (sized.length === 0) {
      el.innerHTML = '<p class="wallet-empty">Нет данных для карты за этот период.</p>';
      return;
    }

    // clientWidth 0 — контейнер сейчас невидим (см. комментарий у
    // lastStructureData) либо среда без реального layout-движка (jsdom-тест,
    // см. README wallet-web); 600 — тот же порядок ширины, что и вся эта
    // SPA (.card.wide — 900px, минус паддинги/сайдбар).
    var containerW = el.clientWidth || 600;
    el._treemapW = el.clientWidth;
    observeTreemapWidth(el);
    var containerH = treemapHeight(el, containerW);
    el.style.height = containerH + 'px';
    var rects = squarifyTreemap(
      sized.map(function (c) { return parseFloat(c.amount_eq); }),
      containerW,
      containerH
    );

    el.innerHTML = rects
      .map(function (r) {
        var c = sized[r.index];
        var bg = treemapTileColor(r.index);
        var fg = isDarkColor(bg) ? 'var(--surf)' : 'var(--ink)';
        // Мелкие плитки не тянут все три строки текста — режем снизу вверх
        // (сначала пропадает доля, потом сумма), а не мельчим шрифт до
        // нечитаемого: то же решение, что и у самого дизайна (t.fs).
        var showPct = r.h >= 50 && c.pct !== null && c.pct !== undefined;
        var showSum = r.h >= 34;
        var fs = r.w < 70 || r.h < 40 ? 11 : r.w > 160 && r.h > 90 ? 16 : 13;
        return (
          '<div class="treemap-tile" title="' + escapeHtml(structureAreaHintTitle(c)) + '" style="' +
          'left:' + r.x + 'px;top:' + r.y + 'px;width:' + Math.max(0, r.w) + 'px;height:' +
          Math.max(0, r.h) + 'px;background:' + bg + ';color:' + fg + ';font-size:' + fs + 'px">' +
          '<div class="treemap-tile-name">' + escapeHtml(c.account_name) + '</div>' +
          (showSum ? '<div class="treemap-tile-sum">' + fmtEq(c.amount_eq) + '</div>' : '') +
          (showPct ? '<div class="treemap-tile-pct">' + escapeHtml(c.pct) + '%</div>' : '') +
          '</div>'
        );
      })
      .join('');
  }

  // Вызывается и сразу после загрузки данных, и при переключении на вкладку
  // "Структура" (см. switchReportsView) — какое из двух событий наступит
  // вторым, тем и будет построена итоговая карта (см. lastStructureData).
  function renderTreemapIfVisible() {
    if (lastStructureData) renderTreemap(lastStructureData.categories);
  }

  // Иконка категории (Design/.../Отчёты - веб.dc.html: круг на подложке
  // `--sand2` с картинкой по центру, background-image, а не <img>) — та же
  // разметка, что и в макете, только источник картинки настоящий:
  // GET /sync/blobs/:sha256 (blob.cpp) — сессионной куки достаточно,
  // device_id не нужен (см. reports_repo.hpp). background-image, а не <img>,
  // ещё и потому, что деградирует бесшумно: не найдётся/не декодируется —
  // виден просто пустой кружок подложки, а не сломанная иконка браузера.
  // extraClass — "Список операций" (opsRowIconHtml) добавляет свой размер
  // поверх базового .cat-icon, не дублируя разметку с картинкой.
  function categoryIconHtml(sha256, extraClass) {
    if (!sha256) return ''; // "" — SQL NULL (transfer у f_operations_for_period, см. её .sql) или, в остальных отчётах, сюда попасть не должны (account.icon_uuid NOT NULL) — не падать же, если вдруг
    return '<span class="cat-icon' + (extraClass ? ' ' + extraClass : '') +
      '" style="background-image:url(\'/sync/blobs/' + sha256 + '\')"></span>';
  }

  function renderStructureResult(data) {
    var el = document.getElementById('structure-result');
    if (data.categories.length === 0) {
      el.innerHTML = '<p class="wallet-empty">Нет расходов за этот период.</p>';
      return;
    }
    var showCmp = data.compared;
    var head =
      '<tr><th>Категория</th><th>Сумма (экв.)</th><th>Доля</th>' +
      (showCmp ? '<th>Было</th><th>Сдвиг</th>' : '') +
      '</tr>';
    var rows = data.categories
      .map(function (row) {
        var barWidth = row.pct === null || row.pct === undefined ? 0 : row.pct;
        var nameCell =
          '<div class="cat-name-row">' + categoryIconHtml(row.icon_sha256) +
          '<div class="cat-name-col">' +
          '<div>' + escapeHtml(row.account_name) + '</div>' +
          '<div class="reports-bar"><div class="reports-bar-fill" style="width:' +
          escapeHtml(String(barWidth)) + '%"></div></div>' +
          '</div></div>';
        var cmpCells = showCmp
          ? '<td>' + pctText(row.pct_before) + '</td><td>' + ppDeltaHtml(row.pp_delta) + '</td>'
          : '';
        return (
          '<tr><td>' + nameCell + '</td>' +
          '<td>' + formatStructureAmount(row.amount_eq) + '</td>' +
          '<td>' + pctText(row.pct) + '</td>' +
          cmpCells + '</tr>'
        );
      })
      .join('');
    var totalColspan = showCmp ? 4 : 2;
    el.innerHTML =
      '<table class="reports-table"><thead>' + head + '</thead>' +
      '<tbody>' + rows + '</tbody>' +
      '<tfoot><tr><td>Итого</td><td>' + reportTotalHtml(data) + '</td>' +
      '<td colspan="' + (totalColspan - 1) + '"></td></tr></tfoot></table>';
  }

  function refreshStructure() {
    var el = document.getElementById('structure-result');
    el.innerHTML = '<p class="sub">Загрузка…</p>';

    var fromStr = document.getElementById('period-from').value;
    var toStr = document.getElementById('period-to').value;
    var params = {
      from: fromStr + 'T00:00:00',
      to: toStr + 'T23:59:59',
      eq_currency: eqCurrencyValue(),
    };

    var cmpMode = document.getElementById('structure-cmp-mode').value;
    var cmpRange = computeCmpRange(cmpMode, fromStr, toStr);
    if (cmpRange) {
      params.cmp_from = isoDate(cmpRange.from) + 'T00:00:00';
      params.cmp_to = isoDate(cmpRange.to) + 'T23:59:59';
    }

    fetchReport('expense-structure', params)
      .then(function (data) {
        if (!data) return;
        lastStructureData = data;
        renderStructureResult(data);
        renderTreemapIfVisible();
        renderOverviewMiniStructure();
      })
      .catch(function (err) {
        el.innerHTML = reportsErrorHtml('Не удалось загрузить структуру расходов: ' + err.message);
      });
  }

  // "Категории во времени" (Design/.../Отчёты - веб.dc.html, экран "cats") —
  // по прямому запросу, карточки по умолчанию — топ-12 ПО РАЗМЕРУ (основные
  // затраты), не по изменению, как в дизайне: там ровно 12 категорий
  // выдуманы заранее, и "показать все" случайно совпадает с любой
  // сортировкой; в реальной схеме категорий может быть сколько угодно,
  // поэтому какие именно 12 попадут на экран по умолчанию — решает сумма за
  // выбранный период, а не дельта. Сам catsAll при этом держит ВСЕ категории
  // целиком (2026-09-11, по прямому запросу — "выбрать любую категорию, не
  // только первые 12, поиском"): поиск (#cats-search) ищет по catsAll, топ-12
  // — лишь вид по умолчанию, см. catsVisibleList.
  //
  // Окно/группировка — генерализованы 2026-09-11 (по прямому запросу, тот же
  // принцип, что и у "Динамики", см. её раздел выше): раньше это было
  // ФИКСИРОВАННОЕ окно в 24 месяца [12 сравнения + 12 текущих], независимо
  // от period-from/-to — теперь окно = сам выбранный период плюс период
  // сравнения ТОЙ ЖЕ длины ДО него (reportsWindowWithComparison), разбитый
  // на бакеты выбранной группировки (#period-group, groupByValue).
  //
  // НИ ОДНОЙ новой SQL-функции — тот же приём, что и "Динамика": переиспользуем
  // GET /api/reports/operations (плоский список операций,
  // reports_repo.hpp::operations_for_period) и группируем по (категория,
  // бакет) уже здесь, на клиенте — сервис такую группировку в SQL сознательно
  // не делает нигде (см. README wallet-api/schema/function про операции:
  // "поиск/фильтр/группировка — уже на стороне сервиса, не в SQL").
  //
  // Урезано относительно дизайна: там ещё есть линия "доля категории в
  // расходах месяца" (catShare) — потребовала бы отдельного похода за суммой
  // расхода КАЖДОГО бакета целиком (income-expense-by-month), только ради
  // одной вспомогательной линии; опущена, как и "среднее за 3" на "Динамике"
  // (см. её комментарий выше про тот же принцип урезания).

  var catsBuckets = [];   // bucket_start окна [prevFrom..curTo], от старого к новому — индекс в monthly[] у каждой категории, см. refreshCategories
  var catsSplitIndex = 0; // индекс первого "текущего" (не приглушённого) бакета — см. bucketSplitIndex
  var catsAll = [];       // ВСЕ категории (не только топ-12) {uuid, name, icon, monthly:[N чисел], cur, prev}, desc по cur
  var catsSelected = null; // uuid текущей выбранной в графике категории
  var catsIncomplete = false;
  var catsQuery = '';      // поиск по названию (#cats-search) — см. catsVisibleList

  // Разбор operations_for_period в catsAll — как opsTopCategoriesHtml выше,
  // курс не нашёлся (amount_eq "" -> NaN) тихо пропускает ЭТУ строку, а не
  // считает её нулём (тот же приём, что и в "Списке операций"); operations
  // вне запрошенного окна теоретически невозможны (сервис сам режет по
  // from/to), но пропущенный индекс на всякий случай просто пропускает такую
  // строку, а не роняет всю агрегацию.
  function buildCatsFromOperations(rows) {
    var groupBy = groupByValue();
    var idxByStart = {};
    catsBuckets.forEach(function (b, i) { idxByStart[b] = i; });
    var byUuid = {};
    rows.forEach(function (r) {
      if (r.kind !== 'expense' || !r.category_uuid) return;
      var eq = parseFloat(r.amount_eq);
      if (isNaN(eq)) return;
      var idx = idxByStart[bucketStart(r.date.slice(0, 10), groupBy)];
      if (idx === undefined) return;
      var c = byUuid[r.category_uuid];
      if (!c) {
        c = byUuid[r.category_uuid] = {
          uuid: r.category_uuid, name: r.category_name, icon: r.icon_sha256,
          monthly: catsBuckets.map(function () { return 0; }),
        };
      }
      c.monthly[idx] += eq;
    });
    var list = Object.keys(byUuid).map(function (u) { return byUuid[u]; });
    list.forEach(function (c) {
      c.cur = c.monthly.slice(catsSplitIndex).reduce(function (a, b) { return a + b; }, 0);
      c.prev = c.monthly.slice(0, catsSplitIndex).reduce(function (a, b) { return a + b; }, 0);
    });
    list.sort(function (a, b) { return b.cur - a.cur; });
    catsAll = list; // ПОЛНЫЙ список — топ-12 теперь только вид по умолчанию карточек, см. catsVisibleList
  }

  // Что показать в сетке карточек — топ-12 по умолчанию (пустой поиск), либо
  // все категории, чьё название содержит запрос (по прямому запросу, поиск —
  // без ограничения в 12, иначе саму мысль "найти скрытую за топ-12
  // категорию" смысла нет). renderCatsChart ищет catsSelected в ПОЛНОМ
  // catsAll, а не в этом отфильтрованном виде — значит выбранная поиском
  // категория остаётся на графике выше, даже когда поиск потом очистили и
  // карточки вернулись к топ-12.
  function catsVisibleList() {
    var q = catsQuery.trim().toLowerCase();
    if (!q) return catsAll.slice(0, 12);
    return catsAll.filter(function (c) { return c.name.toLowerCase().indexOf(q) >= 0; });
  }

  function catsCardHtml(c) {
    var recent = c.monthly.slice(catsSplitIndex);
    var mx = Math.max.apply(null, recent) || 1;
    var bars = recent
      .map(function (v) { return '<div class="cats-card-bar" style="height:' + Math.max(2, Math.round((v / mx) * 100)) + '%"></div>'; })
      .join('');
    var chip = c.prev > 0 ? kpiChipHtml(String(c.cur), String(c.prev), 'down') : '';
    return (
      '<div class="cats-card' + (c.uuid === catsSelected ? ' active' : '') + '" data-cats-cat="' + c.uuid + '">' +
      '<div class="cats-card-head">' + categoryIconHtml(c.icon, 'cats-card-icon') +
      '<div class="cats-card-name">' + escapeHtml(c.name) + '</div></div>' +
      '<div class="cats-card-bars">' + bars + '</div>' +
      '<div class="cats-card-foot"><span class="cats-card-sum">' + fmtEq(c.cur.toFixed(2)) + '</span>' + chip + '</div>' +
      '</div>'
    );
  }

  function renderCatsCards() {
    var el = document.getElementById('cats-cards');
    if (!el) return;
    if (!catsAll.length) {
      el.innerHTML = '<p class="wallet-empty">Нет расходов за выбранный период.</p>';
      return;
    }
    var visible = catsVisibleList();
    el.innerHTML =
      (visible.length ? visible.map(catsCardHtml).join('') : '<p class="wallet-empty">Ничего не найдено.</p>') +
      (catsIncomplete ? '<div class="treemap-note">~ у части операций не нашёлся курс — суммы занижены</div>' : '');
  }

  // Верхняя панель — заголовок+4 статистики выбранной категории и график по
  // ВСЕМ бакетам окна (до catsSplitIndex — период сравнения, приглушены, см.
  // .chart-bar-before в style.css). Клик по карточке/строке поиска ниже (см.
  // wireCatsEvents) меняет catsSelected и зовёт эту функцию заново, без
  // похода в сеть — категория ищется в ПОЛНОМ catsAll (не только в топ-12
  // текущего вида карточек, см. catsVisibleList), значит сюда попадает и
  // категория, найденная поиском.
  function renderCatsChart() {
    var el = document.getElementById('cats-chart');
    if (!el) return;
    if (!catsAll.length) {
      el.innerHTML = '<p class="wallet-empty">Нет расходов за выбранный период.</p>';
      return;
    }
    var groupBy = groupByValue();
    var c = catsAll.filter(function (x) { return x.uuid === catsSelected; })[0] || catsAll[0];
    catsSelected = c.uuid;

    var maxVal = Math.max.apply(null, c.monthly) || 1;
    var bars = c.monthly.map(function (v, i) {
      var h = Math.round((v / maxVal) * 100);
      var label = bucketAxisLabel(catsBuckets[i], groupBy);
      // Без title — по прямому запросу ("хинт на графики всегда такой, как в
      // 'Расход по месяцам'"), см. wireCatsChartCrosshair ниже вместо
      // нативной всплывашки с задержкой браузера. data-cats-bucket — по
      // прямому запросу ("клик по колонке — переход в 'Список операций' с
      // фильтром по этому периоду и категории"), см. wireCatsEvents ниже,
      // тот же приём "детализации", что и .dyn-bar-col/goToMonthDetail.
      var beforeCls = i < catsSplitIndex ? ' chart-bar-before' : '';
      return (
        '<div class="month-bar-col cats-bar-col' + beforeCls + '" data-cats-bucket="' + catsBuckets[i] + '">' +
        '<div class="month-bars"><div class="month-bar expense" style="height:' + h + '%"></div></div>' +
        '<div class="month-label">' + label + '</div></div>'
      );
    }).join('');

    var curMonthly = c.monthly.slice(catsSplitIndex);
    var curCount = curMonthly.length;
    var avg = curCount ? c.cur / curCount : 0;
    var maxMonth = Math.max.apply(null, curMonthly) || 0;
    var deltaChip = c.prev > 0 ? kpiChipHtml(String(c.cur), String(c.prev), 'down') : '<span class="wallet-empty">—</span>';
    // Медиана расхода — по прямому запросу, тем же приёмом (renderMedianLines),
    // что на "Обзоре"/"Динамике", но всего ОДНА линия: тут нет второй серии
    // "доход", категория — это всегда расход. Считается по ТЕКУЩЕМУ периоду
    // (curMonthly, БЕЗ приглушённых бакетов сравнения) — та же область, что и
    // у соседнего "В среднем" чуть выше: одна и та же выборка, среднее и
    // медиана рядом должны отвечать на один вопрос ("сколько ТИПИЧНО тратится
    // в {groupBy} СЕЙЧАС"), а не сравнивать разные окна.
    var hasMedianLine = curCount >= 2;
    var catMedian = hasMedianLine ? median(curMonthly) : null;

    el.innerHTML =
      '<div class="cats-sel-head">' + categoryIconHtml(c.icon, 'cats-sel-icon') +
      '<div class="cats-sel-name">' + escapeHtml(c.name) + '</div>' +
      '<div class="dyn-sel-stats cats-sel-stats">' +
      dynStatHtml('За период', fmtEq(c.cur.toFixed(2))) +
      dynStatHtml('В среднем в ' + GROUP_UNIT[groupBy].acc, fmtEq(avg.toFixed(2))) +
      dynStatHtml('Максимум ' + GROUP_UNIT[groupBy].gen, fmtEq(maxMonth.toFixed(2))) +
      dynStatHtml('К предыдущему периоду', deltaChip) +
      '</div></div>' +
      '<div class="month-chart dyn-chart-wide">' + bars + '</div>' +
      '<div class="treemap-note">' +
      (catsSplitIndex > 0 ? 'Приглушённые столбцы — период сравнения, той же длины, что и выбранный. ' : '') +
      (hasMedianLine ? 'Пунктир — медиана расхода за текущий период. ' : '') +
      'Нажмите карточку категории ниже, чтобы сменить, или столбец — чтобы открыть операции этого периода.</div>';

    var chartEl = el.querySelector('.month-chart');
    thinAxisLabels(chartEl); // ДО оверлеев — см. renderOverviewMonthlyChart
    if (hasMedianLine) renderMedianLines(chartEl, '.cats-bar-col', [{ value: catMedian, cls: 'expense' }], maxVal);
    wireCatsChartCrosshair(chartEl, c.monthly, catsBuckets, groupBy, catMedian);
  }

  // Один делегированный обработчик на карточки — тем же приёмом, что
  // wireOpsEvents: карточки перестраиваются целиком при каждом клике
  // (подсветка active), навешивать слушатель на каждую заново не нужно.
  // Поле поиска (#cats-search) — статичная разметка вне #cats-cards (та же
  // причина, что и у #wallet-search/#cur-search: не перестраивается при
  // renderCatsCards, слушатель вешается один раз за весь заход на "Отчёты").
  function wireCatsEvents() {
    document.getElementById('view-cats').addEventListener('click', function (ev) {
      // Столбец графика — раньше карточки, чтобы клик по бару НЕ читался
      // заодно как клик по карточке (у обоих селекторов разные data-атрибуты,
      // пересечься им негде, но порядок проверки — тот же приём "сначала
      // самый специфичный обработчик", что и в wireOpsEvents).
      var barEl = ev.target.closest('[data-cats-bucket]');
      if (barEl) {
        var bStart = barEl.getAttribute('data-cats-bucket');
        goToOperationsForCategory(bStart, bucketEnd(bStart, groupByValue()), catsSelected);
        return;
      }
      var el = ev.target.closest('[data-cats-cat]');
      if (!el) return;
      catsSelected = el.getAttribute('data-cats-cat');
      renderCatsChart();
      renderCatsCards();
    });
    var searchEl = document.getElementById('cats-search');
    if (searchEl) {
      searchEl.addEventListener('input', function () {
        catsQuery = searchEl.value;
        renderCatsCards();
      });
    }
  }

  function refreshCategories() {
    var chartEl = document.getElementById('cats-chart');
    var cardsEl = document.getElementById('cats-cards');
    if (!chartEl) return; // вкладка 'cats' ещё не построена
    chartEl.innerHTML = '<p class="sub">Загрузка…</p>';
    cardsEl.innerHTML = '<p class="sub">Загрузка…</p>';
    // Новый период — прежний поиск к нему не привязан (тот же приём, что и
    // walletQuery у "Кошельков", см. refreshWalletBalances).
    catsQuery = '';
    var searchEl = document.getElementById('cats-search');
    if (searchEl) searchEl.value = '';

    // Окно — сам выбранный период плюс период сравнения ТОЙ ЖЕ длины ДО
    // него, разбитый на бакеты выбранной группировки — тот же приём, что и
    // у refreshDynamics() (см. её комментарий).
    var fromStr = document.getElementById('period-from').value;
    var toStr = document.getElementById('period-to').value;
    var groupBy = groupByValue();
    var win = reportsWindowWithComparison(fromStr, toStr);
    catsBuckets = buildBuckets(win.prevFrom, win.curTo, groupBy);
    catsSplitIndex = bucketSplitIndex(catsBuckets, win.curFrom);

    fetchAllOperations({
      from: win.prevFrom + 'T00:00:00', to: win.curTo + 'T23:59:59', eq_currency: eqCurrencyValue(),
    })
      .then(function (data) {
        if (!data) return;
        catsIncomplete = data.incomplete;
        buildCatsFromOperations(data.operations);
        // Автовыбор — самая крупная категория; при переключении карточкой/
        // поиском (см. wireCatsEvents) выбор остаётся, пока категория ещё
        // встречается в данных нового периода, иначе сбрасывается на самую
        // крупную.
        var stillTop = catsAll.filter(function (c) { return c.uuid === catsSelected; }).length > 0;
        if (!stillTop) {
          catsSelected = catsAll.length ? catsAll[0].uuid : null;
        }
        renderCatsCards();
        renderCatsChart();
      })
      .catch(function (err) {
        chartEl.innerHTML = reportsErrorHtml('Не удалось загрузить категории во времени: ' + err.message);
      });
  }

  // "Кошельки и остатки" (Design/.../Отчёты - веб (офлайн).html, вид 'wal',
  // по прямому запросу "реализуй Кошельки и остатки из дизайна") — остаток
  // каждого счёта на начало/конец периода, обороты за период и разбивка по
  // валюте.
  //
  // НИ ОДНОЙ новой SQL-функции под сами остатки — переиспользование уже
  // существующего GET /api/reports/balance (см. reports_repo.hpp), тем же
  // приёмом "день ПОСЛЕ конца периода", что и KPI "Обзора" (см. refreshPeriod
  // выше): один раз на periodFrom (то, что накопилось ДО этой даты — как раз
  // "на начало периода", f_balance_to_date считает строго до даты), один раз
  // на день после periodTo ("на конец периода"). Единственный НОВЫЙ запрос —
  // GET /api/reports/wallet-turnover (reports_repo.hpp::wallet_turnover_for_period):
  // "пришло"/"ушло" за период в своей валюте, которых ни у /balance, ни у
  // /income, /expense нет (те либо не про обороты, либо не видят переводов
  // кошелёк -> кошелёк).
  var walletCurrentEqUuid = ''; // eq_currency_uuid последнего /balance — formatEqAmount строк таблицы нужен именно он, не #eq-currency

  // Сортировка таблицы (по прямому запросу) — клик по заголовку столбца, тот
  // же общий приём, что и wireAdminTableSorting у "Пользователей", но БЕЗ
  // перестановки DOM-узлов по текстовому сравнению: тут смешанные валюты и
  // деньги, сортировать нужно по ЧИСЛУ (см. sortWalletRows), а не по тому, как
  // сумма отформатирована на экране. key — 'name' или одно из *EqNum-полей
  // buildWalletRows ('startEqNum'/'inEqNum'/'outEqNum'/'endEqNum' — ПО
  // ЭКВИВАЛЕНТУ, не по своей валюте кошелька: она у разных кошельков разная
  // и несравнима напрямую, по прямому запросу), см. data-sort-key в разметке
  // заголовка (renderReports).
  var walletSort = { key: 'name', dir: 'asc' };

  // Быстрый фильтр (по прямому запросу — "можно вводить и валюту EUR") —
  // текст ищется по названию/типу кошелька И по его валюте (символ, ISO-код,
  // название), см. walletMatchesQuery. Сбрасывается при каждом refreshWalletBalances
  // (новый период) — тот же приём, что у opsState.q в "Списке операций".
  var walletQuery = '';

  // Последние построенные строки (см. buildWalletRows) — клик по заголовку
  // сортировки/ввод в поиск пересортировывают и перефильтровывают ИХ, без
  // повторного похода в сеть (те же данные периода не изменились).
  var walletRowsData = [];

  function balanceRowsByUuid(report) {
    var m = {};
    (report ? report.accounts : []).forEach(function (r) { m[r.account_uuid] = r; });
    return m;
  }

  // Капитальные активы (change capital-assets): asset_type строки
  // wallet-turnover / balance — 1 недвижимость, 2 авто, 3 прочее; null (или
  // поля нет — старый wallet-report) — ликвидный кошелёк (design D7).
  var ASSET_TYPE_LABELS = { 1: 'Недвижимость', 2: 'Авто', 3: 'Прочее' };

  function isAssetRow(w) {
    return w.asset_type !== null && w.asset_type !== undefined;
  }

  function assetTypeLabel(t) {
    return ASSET_TYPE_LABELS[t] || ASSET_TYPE_LABELS[3];
  }

  function walletTagHtml(w, endEq, notInTotal) {
    var tags = '';
    if (isAssetRow(w)) {
      tags += '<span class="wallet-tag wallet-tag-asset">' + assetTypeLabel(w.asset_type).toLowerCase() + '</span>';
      if (notInTotal) tags += '<span class="wallet-tag wallet-tag-asset-out">не в итоге</span>';
    }
    if (w.is_archived) return tags + '<span class="wallet-tag wallet-tag-archived">архивный</span>';
    if (endEq === '') return tags + '<span class="wallet-tag wallet-tag-norate">нет курса</span>';
    return tags;
  }

  // sparkValues — до 12 чисел (own currency, СТАРЫЕ..НОВЫЕ), высота столбца
  // относительно самого большого ПО МОДУЛЮ значения СРЕДИ НИХ (тот же приём,
  // что и WAL.spark в дизайне) — сравнение внутри одного кошелька, не между
  // кошельками с разными оборотами.
  function walletSparkHtml(sparkValues) {
    if (!sparkValues.length) return '';
    var mx = Math.max.apply(null, sparkValues.map(function (v) { return Math.abs(v); })) || 1;
    return sparkValues.map(function (v, i) {
      var h = Math.max(2, Math.round(Math.abs(v) / mx * 26));
      return '<div class="wallet-spark-bar' + (i === sparkValues.length - 1 ? ' current' : '') +
        '" style="height:' + h + 'px"></div>';
    }).join('');
  }

  function walletRowHtml(r) {
    var w = r.w;
    var balCol = parseFloat(r.endAmt) < 0 ? 'var(--exp)' : 'var(--ink)';
    var subText = w.comment ? w.comment + ' · ' + w.symbol : w.symbol;

    return (
      '<div class="wallet-row' + (w.is_archived ? ' archived' : '') +
      '" data-wallet-uuid="' + w.account_uuid + '">' +
      categoryIconHtml(w.icon_sha256, 'wallet-row-icon') +
      '<div class="wallet-row-main">' +
      '<div class="wallet-row-name-line"><span class="wallet-row-name">' + escapeHtml(w.account_name) +
      '</span>' + walletTagHtml(w, r.endEq, r.notInTotal) + '</div>' +
      '<div class="wallet-row-sub">' + escapeHtml(subText) + '</div>' +
      '</div>' +
      '<div class="wallet-spark">' + walletSparkHtml(r.spark) + '</div>' +
      '<div class="wallet-col-amount">' + fmtNative(r.startAmt, w.symbol) + '</div>' +
      '<div class="wallet-col-amount wallet-col-inc">' +
      (parseFloat(w.turnover_in) ? '+' + fmtNative(w.turnover_in, w.symbol) : '—') + '</div>' +
      '<div class="wallet-col-amount wallet-col-exp">' +
      (parseFloat(w.turnover_out) ? '−' + fmtNative(w.turnover_out, w.symbol) : '—') + '</div>' +
      '<div class="wallet-col-end">' +
      '<div style="color:' + balCol + '">' + fmtNative(r.endAmt, w.symbol) + '</div>' +
      '<div class="wallet-col-eq">' + formatEqAmount(w.currency_uuid, walletCurrentEqUuid, r.endEq) + '</div>' +
      '</div></div>'
    );
  }

  // Строит строки таблицы ОДИН раз на период (см. renderWalletTable).
  // *EqNum-поля (startEqNum/inEqNum/outEqNum/endEqNum) существуют специально
  // ради sortWalletRows (по прямому запросу — "сортировка по На конец/
  // Начало/Пришло/Ушло должна быть в эквиваленте, а не валюте кошелька"):
  // "своя" сумма разных кошельков в разных валютах несравнима напрямую,
  // сравнимая величина — только эквивалент. turnover_in_eq/turnover_out_eq
  // сервер отдаёт уже готовыми (wallet-turnover, см. reports_repo.hpp);
  // startEqNum/endEqNum — balance_eq из соответствующего блока
  // balance-at-dates. null (не 0!) — курса вообще не нашлось (см.
  // sortWalletRows, "в конец списка", тот же смысл NULLS LAST, что и в SQL).
  // isoCode/currencyName — из уже загруженного справочника валют
  // (currencyDirectory, см. loadCurrencies), нужны только walletMatchesQuery
  // ниже — сама строка wallet-turnover их не отдаёт (только symbol).
  function buildWalletRows(wallets, balStart, balEnd, sparkByUuid) {
    var startByUuid = balanceRowsByUuid(balStart);
    var endByUuid = balanceRowsByUuid(balEnd);
    return wallets.map(function (w) {
      var startRow = startByUuid[w.account_uuid];
      var endRow = endByUuid[w.account_uuid];
      var startAmt = startRow ? startRow.balance : '0';
      var endAmt = endRow ? endRow.balance : '0';
      var startEq = startRow ? startRow.balance_eq : '';
      var endEq = endRow ? endRow.balance_eq : '';
      var c = currencyDirectory.filter(function (x) { return x.uuid === w.currency_uuid; })[0];
      return {
        w: w,
        isoCode: c ? c.iso_code : '',
        currencyName: c ? c.name : '',
        startAmt: startAmt, startEqNum: startEq === '' ? null : parseFloat(startEq),
        inEqNum: parseFloat(w.turnover_in_eq) || 0,
        outEqNum: parseFloat(w.turnover_out_eq) || 0,
        endAmt: endAmt, endEq: endEq, endEqNum: endEq === '' ? null : parseFloat(endEq),
        spark: sparkByUuid[w.account_uuid] || [],
        // Группа — по asset_type строки wallet-turnover (там все кошельки,
        // и без движения); «не в итоге» — include_in_net_worth строки того же
        // счёта в блоке на конец (design D2): нет строки — нет тега.
        isAsset: isAssetRow(w),
        notInTotal: !!endRow && endRow.include_in_net_worth === false,
      };
    });
  }

  // "можно вводить и валюту EUR" (по прямому запросу) — ищет по названию и
  // типу (comment) кошелька, ЛИБО по его валюте: символу ("₽"), ISO-коду
  // ("EUR") или полному названию ("Евро") разом, без учёта регистра.
  function walletMatchesQuery(r, q) {
    if (!q) return true;
    var hay = (r.w.account_name + ' ' + r.w.comment + ' ' + r.w.symbol + ' ' +
      r.isoCode + ' ' + r.currencyName).toLowerCase();
    return hay.indexOf(q) >= 0;
  }

  function sortWalletRows(rows) {
    var key = walletSort.key;
    var dir = walletSort.dir === 'asc' ? 1 : -1;
    var sorted = rows.slice();
    sorted.sort(function (a, b) {
      if (key === 'name') return a.w.account_name.localeCompare(b.w.account_name, 'ru') * dir;
      var av = a[key], bv = b[key];
      // null — курса не нашлось (см. buildWalletRows) — В КОНЕЦ списка
      // ВСЕГДА, независимо от направления сортировки: тот же смысл
      // "NULLS LAST", что и в ORDER BY ... DESC NULLS LAST у самих SQL-функций.
      if (av === null && bv === null) return 0;
      if (av === null) return 1;
      if (bv === null) return -1;
      return (av - bv) * dir;
    });
    return sorted;
  }

  // Стрелка/подсветка активного заголовка — сама разметка заголовка статична
  // (создаётся один раз в renderReports, см. её же комментарий), перерисовки
  // здесь не требует, только обновление классов/текста стрелки.
  function updateWalletSortHeaderUi() {
    var headEl = document.getElementById('wallet-table-head');
    if (!headEl) return;
    Array.prototype.forEach.call(headEl.querySelectorAll('[data-sort-key]'), function (th) {
      var active = th.getAttribute('data-sort-key') === walletSort.key;
      th.classList.toggle('sorted', active);
      var arrow = th.querySelector('.wallet-sort-arrow');
      if (arrow) arrow.textContent = active ? (walletSort.dir === 'asc' ? '▲' : '▼') : '';
    });
  }

  // Перестраивает саму таблицу из уже построенных walletRowsData — вызывается
  // и после загрузки данных (renderWalletTable), и на каждый клик по
  // заголовку/ввод в поиск (см. wireWalletEvents), БЕЗ повторного похода в
  // сеть — период не менялся, менялись только сортировка/фильтр.
  function renderWalletRowsFromCache() {
    var el = document.getElementById('wallet-table');
    if (!el) return;
    updateWalletSortHeaderUi();
    if (!walletRowsData.length) {
      el.innerHTML = '<p class="wallet-empty">В этом леджере ещё нет ни одного кошелька.</p>';
      return;
    }
    var q = walletQuery.trim().toLowerCase();
    var filtered = walletRowsData.filter(function (r) { return walletMatchesQuery(r, q); });
    if (!filtered.length) {
      el.innerHTML = '<p class="wallet-empty">Ничего не найдено по запросу «' + escapeHtml(walletQuery.trim()) + '».</p>';
      return;
    }
    // Капитальные активы — отдельной группой «Капитал» после ликвидных;
    // сортировка и поиск действуют внутри каждой группы, пустая группа не
    // показывается (в том числе её заголовок).
    var liquid = filtered.filter(function (r) { return !r.isAsset; });
    var assets = filtered.filter(function (r) { return r.isAsset; });
    el.innerHTML = sortWalletRows(liquid).map(walletRowHtml).join('') +
      (assets.length
        ? '<div class="wallet-group-head">Капитал</div>' + sortWalletRows(assets).map(walletRowHtml).join('')
        : '');
  }

  function renderWalletKpis(balStart, balEnd, wallets) {
    var el = document.getElementById('wallet-kpis');
    if (!el) return;
    // parseFloat здесь — как и в renderOverviewKpis, ТОЛЬКО ради разницы двух
    // уже посчитанных сервером сумм для показа стрелки/подписи, не для
    // хранения или дальнейшего суммирования денег (см. reports_repo.hpp,
    // "деньги — numeric").
    // total_eq с парным change wallet-report capital-assets — только
    // ликвидные кошельки; капитал и «всего с капиталом» — отдельные поля
    // ответа (design D1), в браузере не суммируются.
    var delta = parseFloat(balEnd.total_eq) - parseFloat(balStart.total_eq);
    var deltaSub = (delta >= 0 ? 'выросло на ' : 'уменьшилось на ') + fmtEq(Math.abs(delta).toFixed(2));
    var hasAssets = wallets.some(isAssetRow);
    var liquid = wallets.filter(function (w) { return !isAssetRow(w); });
    var activeCount = liquid.filter(function (w) { return !w.is_archived; }).length;
    var archivedCount = liquid.length - activeCount;

    var firstTiles = hasAssets
      ? kpiTileHtml('Ликвидные', (balEnd.incomplete ? '~ ' : '') + fmtEq(balEnd.total_eq), '',
          'эквивалент в ' + eqCurrencySymbol() + ' на конец периода, без капитала') +
        kpiTileHtml('Капитал', (balEnd.capital_incomplete ? '~ ' : '') + fmtEq(balEnd.capital_eq || '0'), '',
          'оценка активов на конец периода') +
        kpiTileHtml('Всего с капиталом',
          (balEnd.incomplete || balEnd.capital_incomplete ? '~ ' : '') + fmtEq(balEnd.net_worth_eq || balEnd.total_eq), '',
          'ликвидные и капитал')
      : kpiTileHtml('Всего в кошельках', (balEnd.incomplete ? '~ ' : '') + fmtEq(balEnd.total_eq), '',
          'эквивалент в ' + eqCurrencySymbol() + ' на конец периода');

    el.innerHTML =
      firstTiles +
      kpiTileHtml('На начало периода', (balStart.incomplete ? '~ ' : '') + fmtEq(balStart.total_eq), '', deltaSub) +
      kpiTileHtml('Активных кошельков', String(activeCount), '',
        archivedCount ? 'и ' + archivedCount + ' архивный, считается наравне' : 'архивных нет');
  }

  function renderWalletTable(wallets, balStart, balEnd, sparkByUuid) {
    if (!document.getElementById('wallet-table')) return;
    walletRowsData = buildWalletRows(wallets, balStart, balEnd, sparkByUuid);
    renderWalletRowsFromCache();
  }

  // Разбивка по валюте (Design/.../Отчёты - веб (офлайн).html, вид 'wal',
  // WAL.byCur) — сумма остатка НА КОНЕЦ периода по каждой валюте кошельков,
  // архивные не участвуют (тот же фильтр, что у items.filter(!arch) в
  // дизайне). own — сумма в СВОЕЙ валюте нескольких кошельков разом:
  // parseFloat+toFixed по precision этой валюты, тот же приём "для показа",
  // что и delta у KPI выше — сервер каждую отдельную сумму уже посчитал
  // numeric, здесь только текстовое сложение для одной строки интерфейса.
  // Флаг (по прямому запросу) — та же categoryIconHtml/icon_sha256, что и у
  // currencyRowHtml пикера валюты эквивалента выше (см. её комментарий): один
  // и тот же механизм "иконка-флаг валюты", просто в другом месте экрана.
  //
  // Секция называется "Состояние по валюте" (по прямому запросу) — обёрнута
  // в <section id="wallet-currencies-section">, скрывается целиком (не
  // просто пустой grid), если после фильтра нулевых сумм показывать нечего.
  // Валюта с нулевой СВОЕЙ суммой (все кошельки этой валюты в сумме дают 0)
  // не показывается вовсе — по тому же прямому запросу: пустая карточка
  // "0.00 USD" не несёт пользы, только шум.
  //
  // "Курс на дату" — раньше отдельный, всегда показанный KPI-тайл наверху
  // (см. историю renderWalletKpis) — убран как общий и бесполезный сам по
  // себе (просто дата периода, не признак проблемы); дата используется
  // здесь, ТОЧЕЧНО, только там, где курса реально не хватает (см. toLabel
  // ниже) — вместо голого "эквивалент неизвестен".
  function renderWalletCurrencies(wallets, balEnd) {
    var el = document.getElementById('wallet-currencies');
    if (!el) return;
    var section = document.getElementById('wallet-currencies-section');
    var endByUuid = balanceRowsByUuid(balEnd);
    var totalEq = parseFloat(balEnd.total_eq) || 0;
    var toStr = document.getElementById('period-to').value;
    var toDate = new Date(toStr + 'T00:00:00');
    var toLabel = toDate.getDate() + ' ' + RU_MONTH_GEN[toDate.getMonth()] + ' ' + toDate.getFullYear();

    var order = [];
    var groups = {};
    wallets.forEach(function (w) {
      // Капитальные активы в «Состояние по валюте» не входят: база доли —
      // total_eq, а он с capital-assets только ликвидные.
      if (w.is_archived || isAssetRow(w)) return;
      var g = groups[w.currency_uuid];
      if (!g) {
        g = groups[w.currency_uuid] = {
          symbol: w.symbol, precision: parseInt(w.precision, 10) || 0, count: 0, ownSum: 0, eqSum: 0, hasEq: true,
        };
        order.push(w.currency_uuid);
      }
      g.count++;
      var endRow = endByUuid[w.account_uuid];
      g.ownSum += endRow ? parseFloat(endRow.balance) || 0 : 0;
      if (endRow && endRow.balance_eq !== '') g.eqSum += parseFloat(endRow.balance_eq);
      else g.hasEq = false;
    });

    // Валюты, чья своя сумма округляется до нуля на её же precision — не
    // показываем (см. комментарий функции выше). toFixed, не сырое ownSum
    // === 0 — тот же приём "для показа", что и у остального в этой функции:
    // почти-ноль (например -0.00000001 после округлений) не должен считаться
    // ненулевым только из-за погрешности float.
    order = order.filter(function (uuid) {
      var g = groups[uuid];
      return parseFloat(g.ownSum.toFixed(g.precision)) !== 0;
    });

    if (!order.length) {
      el.innerHTML = '';
      if (section) section.hidden = true;
      return;
    }
    if (section) section.hidden = false;
    // Сортировка карточек — по эквиваленту убыв. (по прямому запросу:
    // "нижняя разбивка тоже должна сортироваться в эквиваленте, а не
    // размере валюты" — своя сумма разных валют иначе несравнима), группы
    // без курса (hasEq === false) — в конец, тот же смысл NULLS LAST, что и
    // в sortWalletRows/SQL.
    order.sort(function (uuidA, uuidB) {
      var gA = groups[uuidA], gB = groups[uuidB];
      if (!gA.hasEq && !gB.hasEq) return 0;
      if (!gA.hasEq) return 1;
      if (!gB.hasEq) return -1;
      return gB.eqSum - gA.eqSum;
    });
    el.innerHTML = order.map(function (uuid) {
      var g = groups[uuid];
      // Название валюты — из уже загруженного справочника (loadCurrencies,
      // см. renderReports), по uuid (CurrencyRow.uuid), не по symbol: два
      // разных iso_code вполне могут делить один и тот же символ. Справочник
      // мог ещё не прийти (первая отрисовка "Кошельков" раньше ответа
      // GET /api/reports/currencies) — тогда просто пусто, не падаем.
      var c = currencyDirectory.filter(function (x) { return x.uuid === uuid; })[0];
      var pct = g.hasEq && totalEq > 0 ? Math.round(g.eqSum / totalEq * 100) : 0;
      var barCol = uuid === walletCurrentEqUuid ? 'var(--acc)' : 'var(--inc-bar)';
      // Без курса — карточка слегка розовая (по прямому запросу), тем же
      // тоном, что уже отмечает "нет курса" в таблице кошельков (см.
      // .wallet-tag-norate, style.css) — не новый цвет, тот же признак.
      var cardClass = 'wallet-currency-card' + (g.hasEq ? '' : ' wallet-currency-card-norate');
      return (
        '<div class="' + cardClass + '">' +
        '<div class="wallet-currency-head">' + categoryIconHtml(c ? c.icon_sha256 : '', 'wallet-currency-flag') +
        '<span class="wallet-currency-symbol">' + escapeHtml(g.symbol) +
        '</span><span class="wallet-currency-name">' + escapeHtml(c ? c.name : '') + '</span>' +
        '<span class="wallet-currency-pct">' + (g.hasEq ? pct + '%' : '—') + '</span></div>' +
        '<div class="wallet-currency-bar"><div class="wallet-currency-bar-fill" style="width:' + pct +
        '%;background:' + barCol + '"></div></div>' +
        '<div class="wallet-currency-foot">' +
        '<span class="wallet-currency-own">' + fmtNative(g.ownSum.toFixed(g.precision), g.symbol) + '</span>' +
        '<span class="wallet-currency-eq">' +
        (g.hasEq ? '≈ ' + fmtEq(g.eqSum.toFixed(2)) : 'нет курса на ' + toLabel) +
        '</span></div>' +
        '<div class="wallet-currency-count">' + g.count + ' ' + pluralWallet(g.count) + '</div>' +
        '</div>'
      );
    }).join('');
  }

  function pluralWallet(n) {
    return pluralRu(n, ['кошелёк', 'кошелька', 'кошельков']);
  }

  // Спарклайн 12 месяцев (Design/.../Отчёты - веб (офлайн).html, WAL.mons) —
  // ТЕ ЖЕ 12 дат "день после конца месяца", что и линия остатка на графике
  // "Расход по месяцам" "Обзора" (см. refreshPeriod выше, её же комментарий
  // про setDate(1) ДО setMonth()) — если пользователь уже открывал "Обзор" за
  // этот же period-to, все 12 запросов возьмутся из кэша fetchReport целиком,
  // без похода в сеть. Окно НЕЗАВИСИМО от period-from — тот же принцип
  // "последние 12 месяцев" для контекста, не сам выбранный период.
  function walletSparkDates(toStr) {
    var monthFromDate = new Date(toStr + 'T00:00:00');
    monthFromDate.setDate(1);
    monthFromDate.setMonth(monthFromDate.getMonth() - 11);
    var dates = [];
    var mm = new Date(monthFromDate.getTime());
    for (var i = 0; i < 12; i++) {
      var isLast = i === 11;
      var endDate = isLast ? toStr : lastDayOfMonth(isoDate(mm));
      dates.push(isoDate(addDays(new Date(endDate + 'T00:00:00'), 1)));
      mm.setMonth(mm.getMonth() + 1);
    }
    return dates;
  }

  function refreshWalletBalances() {
    var kpisEl = document.getElementById('wallet-kpis');
    var tableEl = document.getElementById('wallet-table');
    var curEl = document.getElementById('wallet-currencies');
    if (!kpisEl) return; // вкладка 'wal' ещё не построена
    [kpisEl, tableEl].forEach(function (e) { e.innerHTML = '<p class="sub">Загрузка…</p>'; });
    curEl.innerHTML = '';
    // Новый период — прежние сортировка/фильтр к нему не привязаны так же
    // жёстко, как opsState.q у "Списка операций" (тот же приём: сбрасываем
    // ТОЛЬКО поиск, сортировка — предпочтение вида, а не фильтр ПОД период,
    // оставляем как было).
    walletQuery = '';
    var searchEl = document.getElementById('wallet-search');
    if (searchEl) searchEl.value = '';

    var eq = eqCurrencyValue();
    var fromStr = document.getElementById('period-from').value;
    var toStr = document.getElementById('period-to').value;
    // "На конец периода" — f_balance_to_date считает строго ДО даты (см.
    // reports_repo.hpp), поэтому день ПОСЛЕ periodTo, та же логика, что у
    // balanceDate KPI "Обзора" (refreshPeriod выше).
    var balanceEndDate = isoDate(addDays(new Date(toStr + 'T00:00:00'), 1));
    var sparkDates = walletSparkDates(toStr);

    // ОДИН батч-запрос на ВСЕ даты разом (начало периода, конец периода, 12
    // точек спарклайна) — по прямому запросу ("сервер научится отдавать
    // балком за период для нескольких кошельков"): раньше здесь уходило до
    // 14 отдельных GET /api/reports/balance. Дубликаты (последняя точка
    // спарклайна нередко совпадает с концом периода) не убираем — сервер
    // посчитает их одинаково, а код без дедупликации проще; индексы 0/1 —
    // начало/конец, дальше — все 12 точек спарклайна В ТОМ ЖЕ ПОРЯДКЕ, что
    // и sparkDates (см. reports_repo.hpp у balances_at_dates — гарантия
    // "ровно один блок на дату, в исходном порядке").
    var allDates = [fromStr, balanceEndDate].concat(sparkDates);

    Promise.all([
      fetchReport('wallet-turnover', { from: fromStr + 'T00:00:00', to: toStr + 'T23:59:59', eq_currency: eq }),
      fetchReport('balance-at-dates', { dates: allDates.join(','), eq_currency: eq }),
    ])
      .then(function (results) {
        var turnover = results[0], batch = results[1];
        if (!turnover || !batch) return; // один из двух — 401, renderLogin() уже вызван внутри fetchReport
        var wallets = turnover.wallets;
        var balStart = batch.dates[0];
        var balEnd = batch.dates[1];
        var sparkBlocks = batch.dates.slice(2);
        walletCurrentEqUuid = batch.eq_currency_uuid;

        renderWalletKpis(balStart, balEnd, wallets);

        var sparkByUuid = {};
        wallets.forEach(function (w) { sparkByUuid[w.account_uuid] = []; });
        sparkBlocks.forEach(function (block) {
          var byUuid = balanceRowsByUuid(block);
          wallets.forEach(function (w) {
            var row = byUuid[w.account_uuid];
            sparkByUuid[w.account_uuid].push(row ? parseFloat(row.balance) || 0 : 0);
          });
        });
        renderWalletTable(wallets, balStart, balEnd, sparkByUuid);
        renderWalletCurrencies(wallets, balEnd);
      })
      .catch(function (err) {
        var msg = reportsErrorHtml('Не удалось загрузить кошельки: ' + err.message);
        kpisEl.innerHTML = msg;
        tableEl.innerHTML = '';
      });
  }

  // Три делегированных обработчика — строки таблицы (переход в "Список
  // операций"), заголовок (сортировка) и поле поиска (фильтр). Заголовок и
  // поле поиска — статичная разметка, созданная один раз в renderReports (не
  // перестраивается при refreshWalletBalances, в отличие от #wallet-table),
  // поэтому слушатель на них вешается ровно один раз за весь заход на
  // "Отчёты" — тот же приём, что и wireCatsEvents/wireOpsEvents.
  function wireWalletEvents() {
    var tableEl = document.getElementById('wallet-table');
    if (tableEl) {
      tableEl.addEventListener('click', function (ev) {
        var row = ev.target.closest('[data-wallet-uuid]');
        if (row) goToOperationsForWallet(row.getAttribute('data-wallet-uuid'));
      });
    }

    var headEl = document.getElementById('wallet-table-head');
    if (headEl) {
      headEl.addEventListener('click', function (ev) {
        var th = ev.target.closest('[data-sort-key]');
        if (!th) return;
        var key = th.getAttribute('data-sort-key');
        if (walletSort.key === key) {
          walletSort.dir = walletSort.dir === 'asc' ? 'desc' : 'asc';
        } else {
          // Деньги — по убыванию первым кликом (крупнейший кошелёк сверху),
          // название — по возрастанию (А→Я): тот же выбор направления "по
          // умолчанию", что интуитивно ждут от каждого типа колонки.
          walletSort.key = key;
          walletSort.dir = key === 'name' ? 'asc' : 'desc';
        }
        renderWalletRowsFromCache();
      });
    }

    var searchEl = document.getElementById('wallet-search');
    if (searchEl) {
      searchEl.addEventListener('input', function () {
        walletQuery = searchEl.value;
        renderWalletRowsFromCache();
      });
    }
  }

  // --- "Капитал" (view 'cap', change capital-assets) ----------------------
  // Капитальные активы — кошельки с отметкой «Капитальный актив» (квартира,
  // машина, прочее; заводятся на телефоне). Источник — GET /api/reports/assets
  // (wallet-report, reportAssets): по активу вложено, переоценка всего и за
  // период, оценка на конец и доходность — всё посчитано сервером.
  //
  // Архивные активы (проданные) экран не показывает ни в таблице, ни в
  // плитках, поэтому плитки — сумма *_eq НЕархивных строк, а не итоги ответа
  // (те — по всем активам). Строки уже округлены сервером, так что сумма
  // строк совпадает с его итогом, когда архивных нет. 404 — wallet-report ещё
  // без ручки (design D7): пустой экран, не ошибка.
  var capitalEqCurrencyUuid = ''; // eq_currency_uuid ответа — formatEqAmount сравнивает с ним валюту актива
  var capitalEqDecimals = 2; // знаков у эквивалента — по строке итога ответа (precision валюты эквивалента)

  function capitalSignedEq(numStr) {
    var v = parseFloat(numStr) || 0;
    return (v > 0 ? '+' : v < 0 ? '−' : '') + fmtEq(Math.abs(v).toFixed(capitalEqDecimals));
  }

  function capitalSignedNative(numStr, symbol) {
    var v = parseFloat(numStr) || 0;
    return (v > 0 ? '+' : v < 0 ? '−' : '') + fmtNative(String(numStr).replace(/^-/, ''), symbol);
  }

  function capitalEmptyHtml() {
    return '<p class="wallet-empty">Капитальных активов пока нет.<br>' +
      'Актив заводится в приложении на телефоне: кошелёк с отметкой «Капитальный актив».</p>';
  }

  function capitalSum(rows, field) {
    var sum = 0, incomplete = false;
    rows.forEach(function (r) {
      if (r[field] === null || r[field] === undefined || r[field] === '') incomplete = true;
      else sum += parseFloat(r[field]);
    });
    return { value: sum.toFixed(capitalEqDecimals), incomplete: incomplete };
  }

  function renderCapitalKpis(rows) {
    var el = document.getElementById('capital-kpis');
    var value = capitalSum(rows, 'value_eq');
    var invested = capitalSum(rows, 'invested_eq');
    var rt = capitalSum(rows, 'revaluation_total_eq');
    var rp = capitalSum(rows, 'revaluation_period_eq');
    el.innerHTML =
      kpiTileHtml('Капитал', (value.incomplete ? '~ ' : '') + fmtEq(value.value), '', 'оценка на конец периода') +
      kpiTileHtml('Вложено', (invested.incomplete ? '~ ' : '') + fmtEq(invested.value), '',
        'переводы в активы минус выводы') +
      kpiTileHtml('Переоценка', (rt.incomplete ? '~ ' : '') + capitalSignedEq(rt.value), '',
        'за период: ' + (rp.incomplete ? '~ ' : '') + capitalSignedEq(rp.value));
  }

  function capitalRowHtml(r) {
    var period = parseFloat(r.revaluation_period)
      ? capitalSignedNative(r.revaluation_period, r.symbol) : '—';
    var pct = r.return_pct === null || r.return_pct === undefined ? '—'
      : (parseFloat(r.return_pct) > 0 ? '+' : parseFloat(r.return_pct) < 0 ? '−' : '') +
        String(r.return_pct).replace(/^-/, '') + ' %';
    var pctCls = parseFloat(r.return_pct) > 0 ? ' capital-up' : parseFloat(r.return_pct) < 0 ? ' capital-down' : '';
    return (
      '<div class="capital-row" data-asset-uuid="' + r.account_uuid + '">' +
      categoryIconHtml(r.icon_sha256, 'wallet-row-icon') +
      '<div class="wallet-row-main">' +
      '<div class="wallet-row-name-line"><span class="wallet-row-name">' + escapeHtml(r.account_name) + '</span>' +
      (r.include_in_net_worth === false ? '<span class="wallet-tag wallet-tag-asset-out">не в итоге</span>' : '') +
      '</div>' +
      '<div class="wallet-row-sub">' + assetTypeLabel(r.asset_type) + ' · ' + escapeHtml(r.symbol) + '</div>' +
      '</div>' +
      '<div class="wallet-col-amount capital-col-wide">' + fmtNative(r.invested, r.symbol) + '</div>' +
      '<div class="wallet-col-amount capital-col-wide">' + capitalSignedNative(r.revaluation_total, r.symbol) + '</div>' +
      '<div class="wallet-col-amount capital-col-wide">' + period + '</div>' +
      '<div class="wallet-col-end">' +
      '<div>' + fmtNative(r.value, r.symbol) + '</div>' +
      '<div class="wallet-col-eq">' +
      formatEqAmount(r.currency_uuid, capitalEqCurrencyUuid, r.value_eq === null ? '' : r.value_eq) + '</div>' +
      '</div>' +
      '<div class="capital-col-pct' + pctCls + '">' + pct + '</div>' +
      '</div>'
    );
  }

  function renderCapital(data) {
    var kpisEl = document.getElementById('capital-kpis');
    var tableEl = document.getElementById('capital-table');
    capitalEqCurrencyUuid = data.eq_currency_uuid;
    capitalEqDecimals = (String(data.value_eq).split('.')[1] || '').length;
    // Порядок — сервер (value_eq убыв., NULLS LAST, затем имя).
    var capitalRows = data.assets.filter(function (r) { return !r.is_archived; });
    if (!capitalRows.length) {
      kpisEl.innerHTML = '';
      tableEl.innerHTML = capitalEmptyHtml();
      return;
    }
    renderCapitalKpis(capitalRows);
    tableEl.innerHTML =
      '<div class="capital-table-head">' +
      '<span></span><span>Актив</span>' +
      '<span class="capital-col-wide">Вложено</span>' +
      '<span class="capital-col-wide">Переоценка</span>' +
      '<span class="capital-col-wide">За период</span>' +
      '<span>Оценка</span><span>Доходность</span>' +
      '</div>' +
      capitalRows.map(capitalRowHtml).join('');
  }

  function refreshCapital() {
    var kpisEl = document.getElementById('capital-kpis');
    var tableEl = document.getElementById('capital-table');
    if (!kpisEl) return; // вкладка 'cap' ещё не построена
    kpisEl.innerHTML = '<p class="sub">Загрузка…</p>';
    tableEl.innerHTML = '';
    var fromStr = document.getElementById('period-from').value;
    var toStr = document.getElementById('period-to').value;
    fetchReport('assets', { from: fromStr + 'T00:00:00', to: toStr + 'T23:59:59', eq_currency: eqCurrencyValue() })
      .then(function (data) { if (data) renderCapital(data); }) // null — 401, renderLogin() уже вызван
      .catch(function (err) {
        if (err.status === 404) {
          kpisEl.innerHTML = '';
          tableEl.innerHTML = capitalEmptyHtml();
          return;
        }
        kpisEl.innerHTML = reportsErrorHtml('Не удалось загрузить капитал: ' + err.message);
        tableEl.innerHTML = '';
      });
  }

  // Клик по активу — «Список операций» того же периода с фильтром по нему
  // (вложения и переоценки), тот же путь с «← Назад», что у кошелька.
  function wireCapitalEvents() {
    var tableEl = document.getElementById('capital-table');
    if (!tableEl) return;
    tableEl.addEventListener('click', function (ev) {
      var row = ev.target.closest('[data-asset-uuid]');
      if (row) goToOperationsForWallet(row.getAttribute('data-asset-uuid'));
    });
  }

  // --- "Доступ и приглашения" (view 'acc') --------------------------------
  // org/docs/TODO_mobile_sync.md, Фаза 6 — перенос экрана `acc` из
  // Design/.../Отчёты - веб.dc.html (state.accVals()/ROLES) поверх РЕАЛЬНОГО
  // API (wallet-api /api/ledger/*, см. его README/openapi.yaml), не поверх
  // фейковой клиентской логики макета (там токен — LCG, ничего не уходит на
  // сервер). Три сознательных отступления от макета — см. комментарии у
  // renderAccessRoot()/accessInviteRowHtml() ниже.

  // Те же три роли, что CHECK у ledger_member.role (wallet-api/schema/table/
  // ledger_member.sql) — подписи те же, что ROLES в дизайн-макете.
  var ACCESS_ROLES = {
    owner: ['Владелец', 'может удалить кошелёк и раздать доступ'],
    member: ['Участник', 'добавляет и правит операции'],
    reader: ['Только чтение', 'видит операции и отчёты, не правит'],
  };
  var ACCESS_TTL_OPTIONS = [2, 7, 30];

  // Черновик формы приглашения — переживает refreshAccess() (тот же приём,
  // что reportsView/walletSort), сбрасывается только новым заходом на
  // "Отчёты" целиком (см. renderReports()).
  var accessInviteRole = 'member';
  var accessInviteTtl = 7;
  // Последний загруженный снимок — renderAccessRoot() рисует ЕГО, не ходит
  // в сеть заново: смена роли/срока в форме и "Копировать" — чисто локальные
  // перерисовки (тот же приём, что renderWalletRowsFromCache() поверх
  // закэшированных строк).
  var accessSnapshot = null; // {members, invites, isOwner}
  // Токен приглашения, которое только что создали, — сервер отдаёт его РОВНО
  // ОДИН РАЗ (POST /api/ledger/invites, см. wallet-api/README.md, "Доступ и
  // приглашения") и никогда больше; живёт только в памяти вкладки.
  var accessJustCreated = null; // {id, role, token, created_at, expires_at}
  var accessCopiedId = null; // id только что скопированного приглашения ('new' — для accessJustCreated) — на 1.5с меняет подпись кнопки

  // Тонкая обёртка над apiFetch для JSON-эндпоинтов wallet-api за пределами
  // /api/reports/* (те свои — см. fetchReport выше, с кэшем по query,
  // здесь кэш не нужен — мутации всегда должны бить по свежим данным).
  // null — 401 (renderLogin() уже вызван), {} — успешный ответ без тела
  // (204).
  function apiJson(url, options) {
    return apiFetch(url, options).then(function (res) {
      if (res.status === 401) {
        renderLogin();
        return null;
      }
      if (res.status === 204) return {};
      return res.json().then(function (data) {
        if (!res.ok) {
          var err = new Error(data && data.error ? data.error : 'HTTP ' + res.status);
          err.status = res.status; // даёт вызывающему коду различать причины (см. acceptPendingInviteIfAny)
          err.body = data; // доп. поля ошибки, напр. ledger_empty у 409 приглашения
          throw err;
        }
        return data;
      });
    });
  }

  function accessDate(iso) {
    var d = new Date(iso);
    return isNaN(d.getTime()) ? iso : d.toLocaleDateString('ru-RU', { day: 'numeric', month: 'long', year: 'numeric' });
  }

  function accessPluralDays(n) {
    var a = Math.abs(n) % 100, b = a % 10;
    if (a > 10 && a < 20) return 'дней';
    if (b > 1 && b < 5) return 'дня';
    if (b === 1) return 'день';
    return 'дней';
  }

  function accessRoleBadgeHtml(role) {
    var label = (ACCESS_ROLES[role] || [role])[0];
    var cls = role === 'owner' ? 'admin' : role === 'member' ? 'ok' : 'user';
    return '<span class="badge ' + cls + '">' + escapeHtml(label) + '</span>';
  }

  // Действия рядом со строкой участника — только если СМОТРЯЩИЙ владелец и
  // строка не его собственная; над строкой самого владельца действий нет
  // вовсе (передача владения — из строки ЦЕЛИ, "Сделать владельцем", а не
  // кнопка у самого владельца, как было в макете — см. renderAccessRoot()).
  function accessMemberActionsHtml(m, isOwnerViewer) {
    if (!isOwnerViewer || m.role === 'owner') return '';
    var otherRole = m.role === 'member' ? 'reader' : 'member';
    return (
      '<button type="button" class="btn-chip" data-access-role="' + escapeHtml(m.user_id) + '" ' +
      'data-role="' + otherRole + '">Сделать «' + escapeHtml(ACCESS_ROLES[otherRole][0]) + '»</button>' +
      '<button type="button" class="btn-chip" data-access-transfer="' + escapeHtml(m.user_id) + '" ' +
      'data-email="' + escapeHtml(m.email) + '">Сделать владельцем</button>' +
      '<button type="button" class="link-btn access-danger" data-access-remove="' + escapeHtml(m.user_id) + '" ' +
      'data-email="' + escapeHtml(m.email) + '">Убрать</button>'
    );
  }

  function accessMemberRowHtml(m, isOwnerViewer) {
    var initial = (m.email || '?').trim().charAt(0).toUpperCase() || '?';
    var isSelf = m.user_id === currentUser.id;
    return (
      '<div class="access-member-row">' +
      '<div class="access-member-avatar">' + escapeHtml(initial) + '</div>' +
      '<div class="access-member-info">' +
      '<div class="access-member-email">' + escapeHtml(m.email || '(без почты)') +
      (isSelf ? ' <span class="access-you">— вы</span>' : '') + '</div>' +
      '<div class="access-member-joined">' + accessRoleBadgeHtml(m.role) +
      '<span>с ' + accessDate(m.joined_at) + '</span></div>' +
      '</div>' +
      '<div class="access-member-actions">' + accessMemberActionsHtml(m, isOwnerViewer) + '</div>' +
      '</div>'
    );
  }

  function accessRoleOptionHtml(role) {
    var info = ACCESS_ROLES[role];
    var active = accessInviteRole === role;
    return (
      '<button type="button" class="access-role-option' + (active ? ' active' : '') +
      '" data-access-set-invite-role="' + role + '">' +
      '<span class="access-role-option-dot"><span></span></span>' +
      '<span><span class="access-role-option-name">' + escapeHtml(info[0]) + '</span>' +
      '<span class="access-role-option-sub">' + escapeHtml(info[1]) + '</span></span>' +
      '</button>'
    );
  }

  function accessTtlButtonHtml(days) {
    var active = accessInviteTtl === days;
    return (
      '<button type="button" class="access-ttl-btn' + (active ? ' active' : '') +
      '" data-access-set-ttl="' + days + '">' + days + ' ' + accessPluralDays(days) + '</button>'
    );
  }

  // БЕЗ кнопки "Копировать" — в отличие от макета: сама ссылка нигде не
  // хранится на сервере (см. wallet-api/README.md, "Доступ и приглашения"),
  // GET /api/ledger/invites её не возвращает вовсе, показать повторно
  // нечего. Обычная практика для секретов "показывается один раз" — важнее
  // точного повтора вида макета.
  function accessInviteRowHtml(inv) {
    return (
      '<div class="access-invite-row">' +
      '<div class="access-invite-meta">' + escapeHtml(ACCESS_ROLES[inv.role][0]) + ' · истекает ' +
      accessDate(inv.expires_at) + ' · создано ' + accessDate(inv.created_at) + '</div>' +
      '<div class="access-invite-actions">' +
      '<button type="button" class="link-btn access-danger" data-access-revoke="' +
      escapeHtml(inv.id) + '">Отозвать</button>' +
      '</div></div>'
    );
  }

  function renderAccessRoot() {
    var root = document.getElementById('access-root');
    if (!root || !accessSnapshot) return;
    var members = accessSnapshot.members, invites = accessSnapshot.invites, isOwner = accessSnapshot.isOwner;

    var membersCard =
      '<section class="access-card">' +
      '<h2>Кто имеет доступ</h2>' +
      members.map(function (m) { return accessMemberRowHtml(m, isOwner); }).join('') +
      (isOwner ? '' :
        '<div class="note" style="margin-top:14px">Приглашать новых участников и менять роли ' +
        'может только владелец.</div>') +
      '</section>';

    var sideHtml = '';
    if (isOwner) {
      var newLinkHtml = '';
      if (accessJustCreated) {
        var link = window.location.origin + '/join/' + accessJustCreated.token;
        newLinkHtml =
          '<div class="access-new-link">' +
          '<div class="access-new-link-value">' + escapeHtml(link) + '</div>' +
          '<button type="button" class="btn-chip" style="width:100%;text-align:center" data-access-copy-new>' +
          (accessCopiedId === 'new' ? 'Скопировано' : 'Копировать') + '</button>' +
          '</div>';
      }
      sideHtml +=
        '<section class="access-card">' +
        '<h2>Пригласить человека</h2>' +
        '<p class="sub" style="margin:4px 0 14px">Ссылку можно отправить в любом мессенджере.</p>' +
        '<div class="access-role-options">' + accessRoleOptionHtml('member') + accessRoleOptionHtml('reader') + '</div>' +
        '<div class="access-ttl-row"><span>Срок ссылки</span><div class="access-ttl-group">' +
        ACCESS_TTL_OPTIONS.map(accessTtlButtonHtml).join('') + '</div></div>' +
        '<button type="button" class="btn" style="width:100%;text-align:center;margin-top:0" ' +
        'id="access-generate-btn">Получить ссылку</button>' +
        '<div class="note" style="margin-top:14px">Ссылка одноразовая: первый, кто войдёт по ней через ' +
        'Google, станет участником с выбранной ролью. Пока по ссылке никто не вошёл, её можно отозвать.</div>' +
        newLinkHtml +
        '</section>';

      if (invites.length > 0) {
        sideHtml +=
          '<section class="access-card">' +
          '<h2>Действующие ссылки</h2>' +
          invites.map(accessInviteRowHtml).join('') +
          '</section>';
      }
    }

    root.innerHTML = '<div class="access-grid"><div>' + membersCard + '</div><div>' + sideHtml + '</div></div>';
  }

  // Копирование в буфер (Clipboard API) — по прямому запросу дизайна
  // ("Копировать"/"Скопировано"). Фолбэк на "тихий успех" без API (страница
  // открыта не по https/не на localhost — свойство недоступно вовсе): showText
  // всё равно на секунду покажет "Скопировано", реальный текст в буфере в
  // этом случае не окажется, но пользователь и так видит ссылку целиком
  // рядом и может выделить её руками — не хуже, чем полное отсутствие кнопки.
  function copyAccessLink(link) {
    var done = function () {
      accessCopiedId = 'new';
      renderAccessRoot();
      setTimeout(function () {
        if (accessCopiedId === 'new') { accessCopiedId = null; renderAccessRoot(); }
      }, 1500);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(link).then(done, done);
    } else {
      done();
    }
  }

  function refreshAccess() {
    var root = document.getElementById('access-root');
    root.innerHTML = '<p class="sub">Загрузка…</p>';
    accessSnapshot = null;

    apiFetch('/api/ledger/members', { credentials: 'include' })
      .then(function (res) {
        if (res.status === 401) { renderLogin(); return null; }
        if (res.status === 404) return { noLedger: true }; // у пользователя ещё нет леджера (см. openapi.yaml)
        return res.json().then(function (data) {
          if (!res.ok) throw new Error(data && data.error ? data.error : 'HTTP ' + res.status);
          return data;
        });
      })
      .then(function (data) {
        if (!data) return null; // 401 — renderLogin() уже вызван
        if (data.noLedger) {
          root.innerHTML = '<p class="sub">У вас пока нет кошелька — приглашать/раздавать доступ нечем.</p>';
          return null;
        }
        var me = data.members.filter(function (m) { return m.user_id === currentUser.id; })[0];
        var isOwner = !!me && me.role === 'owner';
        if (!isOwner) {
          // GET /api/ledger/invites — owner only (403 иначе), не владельцу
          // незачем его вообще звать.
          accessSnapshot = { members: data.members, invites: [], isOwner: false };
          renderAccessRoot();
          return null;
        }
        return apiJson('/api/ledger/invites', { credentials: 'include' }).then(function (invData) {
          accessSnapshot = { members: data.members, invites: (invData && invData.invites) || [], isOwner: true };
          renderAccessRoot();
        });
      })
      .catch(function (err) {
        root.innerHTML = reportsErrorHtml('Не удалось загрузить доступ: ' + err.message);
      });
  }

  function wireAccessEvents() {
    var root = document.getElementById('access-root');
    if (!root) return;

    // Один делегирующий слушатель на контейнер, который сам НИКОГДА не
    // заменяется (только его innerHTML, см. renderAccessRoot()) — тот же
    // приём, что wireWalletEvents()/#wallet-table: слушатель переживает
    // любое число перерисовок.
    root.addEventListener('click', function (ev) {
      var el;

      if ((el = ev.target.closest('[data-access-set-invite-role]'))) {
        accessInviteRole = el.getAttribute('data-access-set-invite-role');
        renderAccessRoot();
        return;
      }
      if ((el = ev.target.closest('[data-access-set-ttl]'))) {
        accessInviteTtl = parseInt(el.getAttribute('data-access-set-ttl'), 10);
        renderAccessRoot();
        return;
      }
      if ((el = ev.target.closest('#access-generate-btn'))) {
        el.disabled = true;
        apiJson('/api/ledger/invites', {
          method: 'POST',
          credentials: 'include',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ role: accessInviteRole, ttl_days: accessInviteTtl }),
        })
          .then(function (invite) {
            if (!invite) return;
            accessJustCreated = invite;
            accessCopiedId = null;
            return refreshAccess();
          })
          .catch(function (err) { window.alert('Не удалось создать приглашение: ' + err.message); })
          .then(function () { if (el.isConnected) el.disabled = false; });
        return;
      }
      if (ev.target.closest('[data-access-copy-new]') && accessJustCreated) {
        copyAccessLink(window.location.origin + '/join/' + accessJustCreated.token);
        return;
      }
      if ((el = ev.target.closest('[data-access-role]'))) {
        var roleUserId = el.getAttribute('data-access-role');
        var role = el.getAttribute('data-role');
        el.disabled = true;
        apiJson('/api/ledger/members/' + encodeURIComponent(roleUserId), {
          method: 'PATCH',
          credentials: 'include',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ role: role }),
        })
          .then(function (res) { if (res) refreshAccess(); else el.disabled = false; })
          .catch(function (err) { window.alert('Не удалось сменить роль: ' + err.message); el.disabled = false; });
        return;
      }
      if ((el = ev.target.closest('[data-access-remove]'))) {
        var removeId = el.getAttribute('data-access-remove');
        var removeEmail = el.getAttribute('data-email');
        if (!window.confirm('Убрать ' + removeEmail + ' из кошелька? Доступ к операциям и отчётам ' +
            'будет отозван немедленно.')) {
          return;
        }
        el.disabled = true;
        apiJson('/api/ledger/members/' + encodeURIComponent(removeId), { method: 'DELETE', credentials: 'include' })
          .then(function (res) { if (res) refreshAccess(); else el.disabled = false; })
          .catch(function (err) { window.alert('Не удалось убрать участника: ' + err.message); el.disabled = false; });
        return;
      }
      if ((el = ev.target.closest('[data-access-transfer]'))) {
        var targetId = el.getAttribute('data-access-transfer');
        var targetEmail = el.getAttribute('data-email');
        if (!window.confirm('Передать владение кошельком пользователю ' + targetEmail + '? Вы сами ' +
            'станете обычным участником — отменить это сможет только новый владелец.')) {
          return;
        }
        el.disabled = true;
        apiJson('/api/ledger/transfer-owner', {
          method: 'POST',
          credentials: 'include',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ user_id: targetId }),
        })
          .then(function (res) { if (res) refreshAccess(); else el.disabled = false; })
          .catch(function (err) { window.alert('Не удалось передать владение: ' + err.message); el.disabled = false; });
        return;
      }
      if ((el = ev.target.closest('[data-access-revoke]'))) {
        var inviteId = el.getAttribute('data-access-revoke');
        el.disabled = true;
        apiJson('/api/ledger/invites/' + encodeURIComponent(inviteId), { method: 'DELETE', credentials: 'include' })
          .then(function (res) { if (res) refreshAccess(); else el.disabled = false; })
          .catch(function (err) { window.alert('Не удалось отозвать приглашение: ' + err.message); el.disabled = false; });
        return;
      }
    });
  }

  // --- "Курсы валют" (view 'cur') -----------------------------------------
  // По прямому запросу пользователя — веб-аналог Android-экранов
  // CurrencyPairListActivity/CurrencyPairRateListActivity/RateEditDialog
  // (просмотр валютных пар и истории их курса, добавление/изменение/
  // удаление пары и её курса) поверх РЕАЛЬНОГО API (wallet-api
  // /api/currency-pairs*, см. его README/openapi.yaml) — тем же приёмом
  // структуры, что и "Доступ и приглашения" выше (один корневой div,
  // полная перерисовка его innerHTML на каждое изменение, один делегирующий
  // слушатель кликов). Список пар — исключение: строки (#cur-rows)
  // перерисовываются отдельно от шапки со строкой поиска (тот же приём, что
  // renderWalletRowsFromCache()/#wallet-search) — иначе поле поиска теряло
  // бы фокус на каждое нажатие клавиши.
  //
  // Сознательно НЕ перенесено с Android: загрузка курсов из внешних
  // источников (Yahoo/Frankfurter/ЦБ РФ) и график истории — отдельная,
  // более крупная задача, не входящая в прямой запрос "добавление/удаление/
  // изменение пары и её курса" (см. README wallet-api, "Курсы валют").

  var curPairs = null;          // [] от GET /api/currency-pairs; null — ещё не загружено
  var curQuery = '';            // поиск по списку пар (символ/ISO/название валюты)
  var curAddFormOpen = false;   // открыта ли мини-форма "Добавить пару" (список)
  var curBaseUuid = '';         // выбранная база/квота в форме "Добавить пару" — см. curPairCurrencyPickerHtml
  var curQuoteUuid = '';
  var curPairPickerOpen = null; // null | 'base' | 'quote' — какой из двух флаговых пикеров формы открыт
  var curDetailPairUuid = null; // null — список пар; иначе — просмотр истории курса этой пары
  var curDetailRates = null;    // [] после загрузки истории текущей пары
  var curRateFormOpen = false;  // открыта ли форма добавления/правки курса (детали)
  var curRateFormEditDate = null; // дата редактируемой строки курса; null — форма для НОВОГО курса
  var curRateFrom = '';         // необязательный фильтр истории (YYYY-MM-DD) — как period-from/-to у отчётов
  var curRateTo = '';
  // Вкладки списка (currency-form-ux, D1): 'pairs' — валютные пары,
  // 'currencies' — справочник валют (currencyDirectory — уже загруженный, без
  // нового запроса). Форма валюты — модальное окно #cur-currency-dialog (D2).
  // curCurrencyForm — null или {uuid|null, name, iso_code, symbol, precision,
  // icon_uuid, icon_sha256, show_in_equivalent, auto, errors}: uuid null —
  // новая валюта; auto — поля, заполненные каталогом (D3), их можно
  // перезаписать следующим пресетом; errors — {name, iso_code, icon, form} (D6).
  var curTab = 'pairs';
  var curCurrencyForm = null;
  var curCurrencyIconPickerOpen = false;
  var curIconQuery = '';          // строка "Поиск флага" (D5)
  var curCurrenciesError = '';    // ошибка удаления валюты — строкой над таблицей (D6)
  var curFlagIcons = null;        // null — грузятся; [] — иконки-флаги (icon_type 1) из GET /api/reports/icons
  var curFlagIconsError = '';

  // Каталог популярных валют для автозаполнения формы новой валюты (D3).
  // flag — слова для поиска иконки-флага по её имени (curFindPresetFlag):
  // ISO-код и страна по-английски, как в именах флагов seed.json телефона
  // ("Flag GEL", "Flag Euro", "Croatian flag"). Точность — минорная
  // единица ISO 4217; у криптовалют — 8, максимум формы.
  var CURRENCY_PRESETS = [
    { iso: 'USD', name: 'Доллар США', symbol: '$', precision: 2, flag: ['USD', 'United States', 'USA', 'America', 'American'] },
    { iso: 'EUR', name: 'Евро', symbol: '€', precision: 2, flag: ['EUR', 'Euro', 'EU', 'Europe', 'European'] },
    { iso: 'RUB', name: 'Российский рубль', symbol: '₽', precision: 2, flag: ['RUB', 'Russia', 'Russian'] },
    { iso: 'GBP', name: 'Фунт стерлингов', symbol: '£', precision: 2, flag: ['GBP', 'United Kingdom', 'UK', 'Britain', 'British'] },
    { iso: 'CHF', name: 'Швейцарский франк', symbol: 'CHF', precision: 2, flag: ['CHF', 'Switzerland', 'Swiss'] },
    { iso: 'JPY', name: 'Японская иена', symbol: '¥', precision: 0, flag: ['JPY', 'Japan', 'Japanese'] },
    { iso: 'CNY', name: 'Китайский юань', symbol: '¥', precision: 2, flag: ['CNY', 'China', 'Chinese'] },
    { iso: 'KZT', name: 'Казахстанский тенге', symbol: '₸', precision: 2, flag: ['KZT', 'Kazakhstan', 'Kazakh'] },
    { iso: 'GEL', name: 'Грузинский лари', symbol: '₾', precision: 2, flag: ['GEL', 'Georgia', 'Georgian'] },
    { iso: 'AMD', name: 'Армянский драм', symbol: '֏', precision: 2, flag: ['AMD', 'Armenia', 'Armenian'] },
    { iso: 'AZN', name: 'Азербайджанский манат', symbol: '₼', precision: 2, flag: ['AZN', 'Azerbaijan', 'Azerbaijani'] },
    { iso: 'BYN', name: 'Белорусский рубль', symbol: 'Br', precision: 2, flag: ['BYN', 'Belarus', 'Belarusian'] },
    { iso: 'UAH', name: 'Украинская гривна', symbol: '₴', precision: 2, flag: ['UAH', 'Ukraine', 'Ukrainian'] },
    { iso: 'UZS', name: 'Узбекский сум', symbol: 'сўм', precision: 2, flag: ['UZS', 'Uzbekistan', 'Uzbek'] },
    { iso: 'KGS', name: 'Киргизский сом', symbol: 'сом', precision: 2, flag: ['KGS', 'Kyrgyzstan', 'Kyrgyz'] },
    { iso: 'TRY', name: 'Турецкая лира', symbol: '₺', precision: 2, flag: ['TRY', 'Turkey', 'Turkish', 'Türkiye'] },
    { iso: 'AED', name: 'Дирхам ОАЭ', symbol: 'AED', precision: 2, flag: ['AED', 'UAE', 'Emirates'] },
    { iso: 'ILS', name: 'Израильский шекель', symbol: '₪', precision: 2, flag: ['ILS', 'Israel', 'Israeli'] },
    { iso: 'THB', name: 'Тайский бат', symbol: '฿', precision: 2, flag: ['THB', 'Thailand', 'Thai'] },
    { iso: 'VND', name: 'Вьетнамский донг', symbol: '₫', precision: 0, flag: ['VND', 'Vietnam', 'Vietnamese'] },
    { iso: 'IDR', name: 'Индонезийская рупия', symbol: 'Rp', precision: 2, flag: ['IDR', 'Indonesia', 'Indonesian'] },
    { iso: 'INR', name: 'Индийская рупия', symbol: '₹', precision: 2, flag: ['INR', 'India', 'Indian'] },
    { iso: 'PLN', name: 'Польский злотый', symbol: 'zł', precision: 2, flag: ['PLN', 'Poland', 'Polish'] },
    { iso: 'CZK', name: 'Чешская крона', symbol: 'Kč', precision: 2, flag: ['CZK', 'Czech', 'Czechia'] },
    { iso: 'HUF', name: 'Венгерский форинт', symbol: 'Ft', precision: 2, flag: ['HUF', 'Hungary', 'Hungarian'] },
    { iso: 'RSD', name: 'Сербский динар', symbol: 'din.', precision: 2, flag: ['RSD', 'Serbia', 'Serbian'] },
    { iso: 'BAM', name: 'Конвертируемая марка', symbol: 'KM', precision: 2, flag: ['BAM', 'Bosnia', 'Bosnian'] },
    { iso: 'ALL', name: 'Албанский лек', symbol: 'L', precision: 2, flag: ['ALL', 'Albania', 'Albanian'] },
    { iso: 'HRK', name: 'Хорватская куна', symbol: 'kn', precision: 2, flag: ['HRK', 'Croatia', 'Croatian'] },
    { iso: 'CAD', name: 'Канадский доллар', symbol: 'C$', precision: 2, flag: ['CAD', 'Canada', 'Canadian'] },
    { iso: 'AUD', name: 'Австралийский доллар', symbol: 'A$', precision: 2, flag: ['AUD', 'Australia', 'Australian'] },
    { iso: 'MXN', name: 'Мексиканское песо', symbol: '$', precision: 2, flag: ['MXN', 'Mexico', 'Mexican'] },
    { iso: 'BRL', name: 'Бразильский реал', symbol: 'R$', precision: 2, flag: ['BRL', 'Brazil', 'Brazilian'] },
    { iso: 'ARS', name: 'Аргентинское песо', symbol: '$', precision: 2, flag: ['ARS', 'Argentina', 'Argentine'] },
    { iso: 'CLP', name: 'Чилийское песо', symbol: '$', precision: 0, flag: ['CLP', 'Chile', 'Chilean'] },
    { iso: 'KES', name: 'Кенийский шиллинг', symbol: 'KSh', precision: 2, flag: ['KES', 'Kenya', 'Kenyan'] },
    { iso: 'TZS', name: 'Танзанийский шиллинг', symbol: 'TSh', precision: 2, flag: ['TZS', 'Tanzania', 'Tanzanian'] },
    { iso: 'USDT', name: 'Tether', symbol: '₮', precision: 2, flag: ['USDT', 'Tether'] },
    { iso: 'USDC', name: 'USD Coin', symbol: 'USDC', precision: 2, flag: ['USDC'] },
    { iso: 'BTC', name: 'Биткоин', symbol: '₿', precision: 8, flag: ['BTC', 'Bitcoin'] },
    { iso: 'ETH', name: 'Эфир', symbol: 'Ξ', precision: 8, flag: ['ETH', 'Ethereum', 'Ether'] },
  ];

  // График истории курса (см. curRateChartHtml/wireCurChart ниже) — состояние
  // перетаскивания диапазона живёт здесь, а не в замыкании одного вызова
  // wireCurChart(): document-level mousemove/mouseup вешаются ОДИН раз на всю
  // жизнь SPA (см. curChartDragWired, тот же приём, что currencyPickerOutsideClickWired
  // у пикера валюты эквивалента), а не заново на каждый renderCurDetail().
  var curChartDrag = null;       // null — не тащим; иначе {svg, selection, asc, startX}
  var curChartDragWired = false;

  function curPairMatchesQuery(p, q) {
    if (!q) return true;
    var hay = [p.symbol, p.base_currency.iso_code, p.base_currency.name,
               p.quote_currency.iso_code, p.quote_currency.name].join(' ').toUpperCase();
    return hay.indexOf(q) >= 0;
  }

  // Сервер отдаёт rate как numeric(24,10)::text — всегда 10 знаков после
  // запятой, включая хвостовые нули ("1.2000000000" для введённого вручную
  // "1.2"), это правильно для точности хранения, но не для показа. Здесь —
  // округление ТОЛЬКО для отображения, до собственной precision пары (тот
  // же приём, что AdapterUtils.getFormat(precision) на Android); само
  // значение на сервер уходит по-прежнему строкой без такого округления
  // (см. wireCurEvents, #cur-save-rate-btn).
  function fmtRate(rateStr, precision) {
    if (!rateStr) return '';
    var n = parseFloat(rateStr);
    if (isNaN(n)) return rateStr;
    return groupThousands(n.toFixed(precision));
  }

  // "+2.34%"/"−1.10%" (см. groupThousands про неразрывный минус) — тот же
  // расчёт, что Android CurrencyPairListAdapter (изменение к курсу ПЕРЕД
  // последним, не за произвольный период).
  function curDeltaHtml(latestStr, prevStr) {
    if (!prevStr) return '';
    var latest = parseFloat(latestStr), prev = parseFloat(prevStr);
    if (!prev) return '';
    var pct = (latest - prev) / prev * 100;
    var cls = pct >= 0 ? 'cur-delta-up' : 'cur-delta-down';
    var sign = pct >= 0 ? '+' : '−';
    return '<span class="' + cls + '">' + sign + Math.abs(pct).toFixed(2) + '%</span>';
  }

  function curPairRowHtml(p) {
    var flags = categoryIconHtml(p.base_currency.icon_sha256, 'wallet-currency-flag') +
                categoryIconHtml(p.quote_currency.icon_sha256, 'wallet-currency-flag');
    var latestHtml = p.latest_rate === ''
      ? '<span class="sub-id">нет курса</span>'
      : fmtRate(p.latest_rate, p.precision) + ' <span class="sub-id">' + escapeHtml(formatDate(p.latest_date)) + '</span>';
    var actionsHtml = p.is_own
      ? '<button type="button" class="btn-force-logout" data-cur-delete-pair="' + escapeHtml(p.uuid) +
        '" data-symbol="' + escapeHtml(p.symbol) + '">Удалить</button>'
      : '<span class="sub-id">общая</span>';
    return (
      '<tr data-cur-open="' + escapeHtml(p.uuid) + '">' +
      '<td>' + flags + ' <strong>' + escapeHtml(p.symbol) + '</strong></td>' +
      '<td>' + latestHtml + '</td>' +
      '<td>' + curDeltaHtml(p.latest_rate, p.prev_rate) + '</td>' +
      '<td>' + actionsHtml + '</td>' +
      '</tr>'
    );
  }

  function renderCurRows() {
    var tbody = document.getElementById('cur-rows');
    if (!tbody || !curPairs) return;
    var q = curQuery.trim().toUpperCase();
    var filtered = curPairs.filter(function (p) { return curPairMatchesQuery(p, q); });
    tbody.innerHTML = filtered.length
      ? filtered.map(curPairRowHtml).join('')
      : '<tr><td colspan="4" class="wallet-empty">' +
        (curPairs.length ? 'Ничего не найдено.' : 'Пар пока нет — добавьте первую выше.') + '</td></tr>';
  }

  // Флаговый пикер валюты для формы "Добавить пару" (по прямому запросу,
  // 2026-09-11 — "добавь иконки валютных пар, флаги стран") — та же
  // разметка/CSS-классы, что и у пикера валюты эквивалента (#eq-currency,
  // см. currencyRowHtml/wireCurrencyPicker выше — обычный <select> не умеет
  // иконку внутри <option> ни в одном браузере), но НЕ тот же синглтон:
  // здесь нужно два НЕЗАВИСИМЫХ инстанса разом (база/квота), поэтому
  // параметризовано kind'ом, а не завязано на фиксированные id.
  //
  // #cur-base-select/#cur-quote-select остаются, как и были, скрытыми
  // input'ами — единственным источником истины для #cur-create-pair-btn
  // (см. wireCurEvents) — сам обработчик создания пары не изменился.
  function curPairCurrencyPickerHtml(kind, selectedUuid) {
    var selected = currencyDirectory.filter(function (c) { return c.uuid === selectedUuid; })[0];
    var buttonHtml = selected
      ? categoryIconHtml(selected.icon_sha256, 'currency-picker-row-flag') +
        '<span>' + escapeHtml(selected.iso_code) + '</span>'
      : '<span class="currency-picker-row-flag"></span><span class="sub-id">Выбрать…</span>';
    var rowsHtml = currencyDirectory.map(function (c) {
      return '<div class="currency-picker-row' + (c.uuid === selectedUuid ? ' active' : '') + '" ' +
        'data-pair-pick="' + kind + '" data-uuid="' + escapeHtml(c.uuid) + '">' +
        categoryIconHtml(c.icon_sha256, 'currency-picker-row-flag') +
        '<span class="currency-picker-row-code">' + escapeHtml(c.iso_code) + '</span>' +
        '<span class="currency-picker-row-name">' + escapeHtml(c.name) + '</span>' +
        '</div>';
    }).join('');

    return (
      '<label class="currency-picker">' +
      '<button type="button" class="currency-picker-btn" data-pair-toggle="' + kind + '">' + buttonHtml + '</button>' +
      '<input type="hidden" id="cur-' + kind + '-select" value="' + escapeHtml(selectedUuid) + '">' +
      '<div class="currency-picker-list"' + (curPairPickerOpen === kind ? '' : ' hidden') + '>' + rowsHtml + '</div>' +
      '</label>'
    );
  }

  function curAddFormHtml() {
    if (!curAddFormOpen) return '';
    return (
      '<div class="cur-add-form">' +
      curPairCurrencyPickerHtml('base', curBaseUuid) +
      curPairCurrencyPickerHtml('quote', curQuoteUuid) +
      '<input type="number" id="cur-precision-input" min="0" max="10" value="5" title="Знаков после запятой">' +
      '<button type="button" class="btn" id="cur-create-pair-btn">Создать</button>' +
      '<button type="button" class="btn btn-secondary" id="cur-cancel-add-btn">Отмена</button>' +
      '</div>'
    );
  }

  // --- справочник валют на "Курсах валют" (currency-ui-tweaks) ------------
  // Запись — REST wallet-api /api/currencies* (createCurrency/updateCurrency/
  // deleteCurrency, см. его openapi.yaml), чтение — тот же
  // GET /api/reports/currencies, что у пикеров эквивалента. Кнопки записи —
  // только у своей валюты (is_own === true: нет поля — старый wallet-report —
  // значит общая, D6) и не в режиме "Посмотреть как клиент" (D5): REST
  // wallet-api пишет в леджер вошедшего, а не просматриваемого.
  function curCurrencyRowHtml(c) {
    var actionsHtml = '<span class="sub-id">общая</span>';
    if (c.is_own === true) {
      actionsHtml = viewAsUser ? '' :
        '<button type="button" class="link-btn" data-cur-edit-currency="' + escapeHtml(c.uuid) + '">Изменить</button> ' +
        '<button type="button" class="link-btn access-danger" data-cur-delete-currency="' + escapeHtml(c.uuid) + '" ' +
        'data-iso="' + escapeHtml(c.iso_code) + '">Удалить</button>';
    }
    var precision = c.precision === undefined || c.precision === null ? '' : String(c.precision);
    return (
      '<tr>' +
      '<td><span class="cur-currency-name">' + categoryIconHtml(c.icon_sha256, 'wallet-currency-flag') +
      '<strong>' + escapeHtml(c.iso_code) + '</strong> <span class="sub-id">' + escapeHtml(c.name) + '</span></span></td>' +
      '<td>' + escapeHtml(c.symbol || '') + '</td>' +
      '<td>' + escapeHtml(precision) + '</td>' +
      '<td>' + (c.show_in_equivalent !== false ? 'да' : 'нет') + '</td>' +
      '<td class="cur-currency-actions">' + actionsHtml + '</td>' +
      '</tr>'
    );
  }

  // --- пикер иконки формы валюты (currency-form-ux, D5) --------------------
  // Кнопка + поле "Поиск флага" + сетка. При вводе в поиск перерисовывается
  // только сетка (#cur-icon-grid), поле остаётся тем же узлом и не теряет
  // фокус; выбор иконки перерисовывает пикер целиком, но не поля формы.
  function curIconGridHtml() {
    var f = curCurrencyForm;
    if (curFlagIconsError) return '<p class="err">Не удалось загрузить иконки: ' + escapeHtml(curFlagIconsError) + '</p>';
    if (curFlagIcons === null) return '<p class="sub">Загрузка…</p>';
    if (!curFlagIcons.length) return '<p class="wallet-empty">Иконок-флагов нет.</p>';
    var q = curIconQuery.trim().toLowerCase();
    var shown = curFlagIcons.filter(function (i) { return !q || String(i.name).toLowerCase().indexOf(q) >= 0; });
    if (!shown.length) return '<p class="wallet-empty">Ничего не найдено.</p>';
    return shown.map(function (i) {
      return '<button type="button" class="cur-icon-cell' + (i.uuid === f.icon_uuid ? ' active' : '') + '" ' +
        'data-cur-pick-icon="' + escapeHtml(i.uuid) + '" data-sha256="' + escapeHtml(i.sha256) + '" ' +
        'title="' + escapeHtml(i.name) + '">' + categoryIconHtml(i.sha256, 'cur-icon-flag') +
        '<span class="cur-icon-caption">' + escapeHtml(i.name) + '</span></button>';
    }).join('');
  }

  function curSelectedIconName() {
    var f = curCurrencyForm;
    var icon = (curFlagIcons || []).filter(function (i) { return i.uuid === f.icon_uuid; })[0];
    return icon ? icon.name : '';
  }

  function curCurrencyIconPickerHtml() {
    var f = curCurrencyForm;
    var name = curSelectedIconName();
    var buttonHtml = f.icon_sha256
      ? categoryIconHtml(f.icon_sha256, 'currency-picker-row-flag') +
        '<span>' + escapeHtml(name || 'Выбрана') + '</span><span class="sub-id">Сменить…</span>'
      : '<span class="currency-picker-row-flag"></span><span class="sub-id">Выбрать…</span>';
    var panelHtml = '';
    if (curCurrencyIconPickerOpen) {
      panelHtml =
        '<input type="search" id="cur-icon-search" class="cur-icon-search" placeholder="Поиск флага" ' +
        'value="' + escapeHtml(curIconQuery) + '" autocomplete="off">' +
        '<div class="cur-icon-grid" id="cur-icon-grid">' + curIconGridHtml() + '</div>';
    }
    return (
      '<button type="button" class="currency-picker-btn' + (f.errors.icon ? ' invalid' : '') + '" id="cur-currency-icon-btn">' +
      buttonHtml + '</button>' +
      curFieldErrorHtml('icon') +
      panelHtml
    );
  }

  function renderCurCurrencyIconPicker() {
    var el = document.getElementById('cur-currency-icon-picker');
    if (el && curCurrencyForm) el.innerHTML = curCurrencyIconPickerHtml();
    renderCurIsoFlag();
  }

  function renderCurIconGrid() {
    var el = document.getElementById('cur-icon-grid');
    if (el && curCurrencyForm) el.innerHTML = curIconGridHtml();
  }

  // Превью флага слева в поле "ISO-код" (D7) — то же, что выбрано в пикере.
  function renderCurIsoFlag() {
    var el = document.getElementById('cur-iso-flag');
    if (el && curCurrencyForm) el.innerHTML = categoryIconHtml(curCurrencyForm.icon_sha256, 'cur-iso-flag-img');
  }

  // Иконки — через fetchReport('icons') при каждом открытии формы: обычно
  // уже в reportsCache (их грузит вкладка "Иконки" при входе в "Отчёты"),
  // тогда без нового запроса. Пресет мог примениться раньше, чем пришли
  // иконки, — тогда флаг подбирается здесь (D4).
  function loadCurFlagIcons() {
    curFlagIcons = null;
    curFlagIconsError = '';
    fetchReport('icons', {})
      .then(function (data) {
        if (!data) return; // 401 — renderLogin() уже вызван
        curFlagIcons = data.user.concat(data.common).filter(function (i) { return String(i.icon_type) === '1'; });
        if (curCurrencyForm && curCurrencyForm.presetIso) {
          curApplyPresetFlag(curPresetByIso(curCurrencyForm.presetIso));
        }
        renderCurCurrencyIconPicker();
      })
      .catch(function (err) {
        curFlagIconsError = err.message;
        renderCurCurrencyIconPicker();
      });
  }

  // --- каталог и автозаполнение (currency-form-ux, D3/D4) -------------------
  function curPresetByIso(iso) {
    var key = String(iso || '').trim().toUpperCase();
    if (!key) return null;
    return CURRENCY_PRESETS.filter(function (p) { return p.iso === key; })[0] || null;
  }

  function curPresetByName(name) {
    var key = String(name || '').trim().toLowerCase();
    if (!key) return null;
    return CURRENCY_PRESETS.filter(function (p) { return p.name.toLowerCase() === key; })[0] || null;
  }

  // Пресеты, которых ещё нет в справочнике, — для подсказок datalist.
  function curAvailablePresets() {
    var have = {};
    currencyDirectory.forEach(function (c) { have[String(c.iso_code).toUpperCase()] = true; });
    return CURRENCY_PRESETS.filter(function (p) { return !have[p.iso]; });
  }

  // Иконка-флаг под подсказки пресета (preset.flag) или null (D4). Имена
  // флагов заданы людьми и не единообразны: "Flag GEL", "Flag Euro",
  // "Bosnian flag", "Croatian flag" (seed.json телефона). Сравнение — по
  // словам целиком, без учёта регистра, а не подстрокой: короткие коды
  // давали бы ложные совпадения ("ALL" в "Small", "RUB" в "Rubble").
  // Подсказка из нескольких слов ("United States") ищется как подряд идущие
  // слова имени. Приоритет — порядок подсказок (ISO-код первым), а не
  // порядок иконок: "Flag USD" побеждает "American flag".
  function curFlagNameWords(name) {
    return String(name || '').toLowerCase().split(/[\s_\-.,()]+/).filter(Boolean);
  }

  function curFindPresetFlag(preset, icons) {
    var named = icons.map(function (i) { return { icon: i, text: ' ' + curFlagNameWords(i.name).join(' ') + ' ' }; });
    for (var h = 0; h < preset.flag.length; h++) {
      var hint = ' ' + curFlagNameWords(preset.flag[h]).join(' ') + ' ';
      if (hint === '  ') continue;
      for (var k = 0; k < named.length; k++) {
        if (named[k].text.indexOf(hint) >= 0) return named[k].icon;
      }
    }
    return null;
  }

  // Флаг из пресета ставится, только если иконка не выбрана или выбрана
  // прошлым пресетом (auto.icon): выбранное руками не перетираем.
  function curApplyPresetFlag(preset) {
    var f = curCurrencyForm;
    if (!preset || !f || !curFlagIcons) return;
    if (f.icon_uuid && !f.auto.icon) return;
    var icon = curFindPresetFlag(preset, curFlagIcons);
    if (!icon) return;
    f.icon_uuid = icon.uuid;
    f.icon_sha256 = icon.sha256;
    f.auto.icon = true;
    f.errors.icon = '';
    if (!curIconQuery) curCurrencyIconPickerOpen = false; // флаг нашёлся — сетка больше не нужна
  }

  // Применение пресета к новой валюте: заполняются только пустые поля и
  // поля, заполненные прошлым пресетом (f.auto); значения в DOM и в
  // curCurrencyForm обновляются вместе. source — поле, которое вызвало
  // совпадение ('iso_code' или 'name'): его не трогаем, пользователь его
  // только что набрал.
  function curApplyPreset(preset, source) {
    var f = curCurrencyForm;
    if (!f || f.uuid || !preset) return;
    f.presetIso = preset.iso;
    var values = { iso_code: preset.iso, name: preset.name, symbol: preset.symbol, precision: String(preset.precision) };
    var ids = { iso_code: 'cur-currency-iso', name: 'cur-currency-name', symbol: 'cur-currency-symbol', precision: 'cur-currency-precision' };
    Object.keys(values).forEach(function (k) {
      if (k === source) return;
      var el = document.getElementById(ids[k]);
      var current = el ? el.value : f[k];
      // Точность новой формы — дефолт "2", не ввод пользователя: считаем её
      // заполненной каталогом с самого начала (openCurCurrencyForm).
      if (current.trim() && !f.auto[k]) return;
      f[k] = values[k];
      f.auto[k] = true;
      if (el) el.value = values[k];
      if (f.errors[k]) { f.errors[k] = ''; curRenderFieldError(k); }
    });
    curApplyPresetFlag(preset);
    curUpdateSymbolPlaceholder();
    renderCurCurrencyIconPicker();
  }

  function curDatalistHtml() {
    var presets = curAvailablePresets();
    return (
      '<datalist id="cur-preset-iso">' + presets.map(function (p) {
        return '<option value="' + escapeHtml(p.iso) + '">' + escapeHtml(p.name) + '</option>';
      }).join('') + '</datalist>' +
      '<datalist id="cur-preset-name">' + presets.map(function (p) {
        return '<option value="' + escapeHtml(p.name) + '">' + escapeHtml(p.iso) + '</option>';
      }).join('') + '</datalist>'
    );
  }

  // --- окно формы валюты (currency-form-ux, D2/D6/D7) -----------------------
  var CUR_FIELD_IDS = { name: 'cur-currency-name', iso_code: 'cur-currency-iso' };

  function curFieldErrorHtml(key) {
    var msg = curCurrencyForm && curCurrencyForm.errors[key];
    // <span>, не <p>: ошибка поля лежит внутри <label class="cur-field">.
    return '<span class="cur-field-error" id="cur-err-' + key + '"' + (msg ? '' : ' hidden') + '>' + escapeHtml(msg || '') + '</span>';
  }

  // Точечное обновление ошибки одного поля — без перерисовки формы, чтобы
  // не сбивать фокус и курсор при вводе.
  function curRenderFieldError(key) {
    var f = curCurrencyForm;
    if (!f) return;
    var msg = f.errors[key] || '';
    var errEl = document.getElementById('cur-err-' + key);
    if (errEl) { errEl.textContent = msg; errEl.hidden = !msg; }
    var input = CUR_FIELD_IDS[key] && document.getElementById(CUR_FIELD_IDS[key]);
    if (input) input.classList.toggle('invalid', !!msg);
    if (key === 'icon') {
      var btn = document.getElementById('cur-currency-icon-btn');
      if (btn) btn.classList.toggle('invalid', !!msg);
    }
    if (key === 'form') {
      var formErr = document.getElementById('cur-form-error');
      if (formErr) { formErr.textContent = msg; formErr.hidden = !msg; }
    }
  }

  function curUpdateSymbolPlaceholder() {
    var iso = document.getElementById('cur-currency-iso');
    var sym = document.getElementById('cur-currency-symbol');
    if (iso && sym) sym.placeholder = iso.value.trim() || 'Как ISO-код';
  }

  function curCurrencyFormHtml() {
    var f = curCurrencyForm;
    var isNew = !f.uuid;
    function field(key, label, id, type, value, extra, prefixHtml) {
      var msg = key && f.errors[key];
      return '<label class="cur-field"><span>' + label + '</span>' +
        (prefixHtml ? '<span class="cur-input-with-flag">' + prefixHtml : '') +
        '<input type="' + type + '" id="' + id + '" value="' + escapeHtml(value) + '"' +
        (msg ? ' class="invalid"' : '') + (extra || '') + '>' +
        (prefixHtml ? '</span>' : '') +
        (key ? curFieldErrorHtml(key) : '') + '</label>';
    }
    return (
      '<form class="cur-dialog-body" method="dialog" novalidate>' +
      '<h2 class="cur-dialog-title">' + (isNew ? 'Новая валюта' : 'Валюта ' + escapeHtml(f.iso_code)) + '</h2>' +
      (isNew ? curDatalistHtml() : '') +
      '<div class="cur-currency-form">' +
      field('iso_code', 'ISO-код', 'cur-currency-iso', 'text', f.iso_code,
        ' maxlength="8" autocapitalize="characters" autocomplete="off" spellcheck="false"' +
        (isNew ? ' list="cur-preset-iso" placeholder="Например GEL"' : ''),
        '<span class="cur-iso-flag" id="cur-iso-flag">' + categoryIconHtml(f.icon_sha256, 'cur-iso-flag-img') + '</span>') +
      field('name', 'Название', 'cur-currency-name', 'text', f.name,
        ' autocomplete="off"' + (isNew ? ' list="cur-preset-name" placeholder="Например Грузинский лари"' : '')) +
      field(null, 'Символ', 'cur-currency-symbol', 'text', f.symbol,
        ' autocomplete="off" placeholder="' + escapeHtml(f.iso_code || 'Как ISO-код') + '"') +
      field(null, 'Точность (знаков после запятой)', 'cur-currency-precision', 'number', f.precision,
        ' min="0" max="8" placeholder="2"') +
      '<div class="cur-field cur-field-wide"><span>Иконка</span>' +
      '<div id="cur-currency-icon-picker">' + curCurrencyIconPickerHtml() + '</div></div>' +
      '<label class="cur-check"><input type="checkbox" id="cur-currency-eq"' + (f.show_in_equivalent ? ' checked' : '') + '> ' +
      'Показывать в эквиваленте</label>' +
      '<p class="err cur-form-error" id="cur-form-error"' + (f.errors.form ? '' : ' hidden') + '>' + escapeHtml(f.errors.form || '') + '</p>' +
      '<div class="cur-currency-form-buttons">' +
      '<button type="button" class="btn" id="cur-save-currency-btn">Сохранить</button>' +
      '<button type="button" class="btn btn-secondary" id="cur-cancel-currency-btn">Отмена</button>' +
      '</div>' +
      '</div>' +
      '</form>'
    );
  }

  function curDialogEl() {
    return document.getElementById('cur-currency-dialog');
  }

  function renderCurCurrencyDialog() {
    var dlg = curDialogEl();
    if (!dlg || !curCurrencyForm) return;
    dlg.innerHTML = curCurrencyFormHtml();
  }

  // Закрытие окна — единственный путь сброса формы: "Отмена", Esc (cancel),
  // клик по затемнению, успешное сохранение, уход с вкладки (D2).
  function closeCurCurrencyDialog() {
    curCurrencyForm = null;
    curCurrencyIconPickerOpen = false;
    curIconQuery = '';
    var dlg = curDialogEl();
    if (!dlg) return;
    if (dlg.open) dlg.close();
    dlg.innerHTML = '';
  }

  function curCurrenciesHtml() {
    if (!currencyDirectory.length) return '<p class="sub">Справочник валют недоступен.</p>';
    return (
      (curCurrenciesError ? '<p class="err">' + escapeHtml(curCurrenciesError) + '</p>' : '') +
      '<div class="users-table-wrap cur-currencies-wrap">' +
      '<table class="users" id="cur-currencies-table">' +
      '<thead><tr><th class="no-sort">Валюта</th><th class="no-sort">Символ</th><th class="no-sort">Точность</th>' +
      '<th class="no-sort">В эквиваленте</th><th class="no-sort">Действия</th></tr></thead>' +
      '<tbody>' + currencyDirectory.map(curCurrencyRowHtml).join('') + '</tbody>' +
      '</table></div>'
    );
  }

  // Писать в справочник можно, если это не режим "Посмотреть как клиент"
  // (currency-ui-tweaks D5) и wallet-report отдаёт is_own (D6).
  function curCanWriteCurrencies() {
    return !viewAsUser && currencyDirectory.some(function (c) { return typeof c.is_own === 'boolean'; });
  }

  // Только блок валют (#cur-currencies) — без пересоздания всего #cur-root:
  // зовётся и из loadCurrencies, когда справочник пришёл после открытия
  // вкладки. Кнопка "Добавить валюту" зависит от справочника (is_own) —
  // обновляется тут же.
  function renderCurCurrencies() {
    var el = document.getElementById('cur-currencies');
    if (!el) return;
    el.innerHTML = curCurrenciesHtml();
    var btn = document.getElementById('cur-add-currency-btn');
    if (btn) btn.hidden = !curCanWriteCurrencies();
  }

  // Тексты 409 записи валюты (currency-ui-tweaks D4) — те же, что у формы
  // валюты на телефоне; иначе — текст ошибки сервера.
  function currencyErrorText(err) {
    var b = err && err.body;
    if (b && b.error === 'duplicate' && b.field === 'iso_code') return 'Валюта с таким кодом уже есть';
    if (b && b.error === 'duplicate' && b.field === 'name') return 'Валюта с таким названием уже есть';
    if (b && b.error === 'currency_in_pair') return 'Код используется в валютной паре';
    if (b && b.error === 'currency_in_use') return 'Валюта используется кошельком или валютной парой — сначала уберите её оттуда';
    return err.message;
  }

  // После записи — перезапрос справочника (D3) и перерисовка списка целиком:
  // таблица валют, флаговые пикеры "Добавить пару" (loadCurrencies сам
  // перерисует пикеры эквивалента).
  function afterCurrencyWrite() {
    reloadCurrencyDirectory().then(function () {
      if (!curDetailPairUuid) renderCurList();
    });
  }

  function openCurCurrencyForm(c) {
    var errors = { name: '', iso_code: '', icon: '', form: '' };
    curCurrencyForm = c
      ? { uuid: c.uuid, name: c.name, iso_code: c.iso_code, symbol: c.symbol || '',
          precision: c.precision === undefined || c.precision === null ? '' : String(c.precision),
          icon_uuid: c.icon_uuid || '', icon_sha256: c.icon_sha256 || '',
          show_in_equivalent: c.show_in_equivalent !== false, auto: {}, errors: errors }
      // Новая: точность "2" (D7) и помечена как заполненная каталогом —
      // пресет с другой точностью (BTC — 8) её заменит. Без флага
      // «В эквиваленте», кроме самой первой в справочнике
      // (openspec currency-eq-default-off; то же правило, что форма на телефоне).
      : { uuid: null, name: '', iso_code: '', symbol: '', precision: '2', icon_uuid: '', icon_sha256: '',
          show_in_equivalent: !currencyDirectory.length, auto: { precision: true }, errors: errors };
    curCurrencyIconPickerOpen = !c; // у новой иконки нет — сетку сразу видно
    curIconQuery = '';
    curCurrenciesError = '';
    renderCurCurrencyDialog();
    var dlg = curDialogEl();
    if (dlg && !dlg.open) dlg.showModal();
    var first = document.getElementById(c ? 'cur-currency-name' : 'cur-currency-iso');
    if (first) first.focus();
    loadCurFlagIcons();
  }

  function renderCurList() {
    var root = document.getElementById('cur-root');
    if (!root) return;
    var onPairs = curTab === 'pairs';
    var tabsHtml =
      '<div class="ops-seg-group cur-tabs">' +
      '<button type="button" class="ops-seg-btn' + (onPairs ? ' active' : '') + '" data-cur-tab="pairs">Валютные пары</button>' +
      '<button type="button" class="ops-seg-btn' + (onPairs ? '' : ' active') + '" data-cur-tab="currencies">Справочник валют</button>' +
      '</div>';
    var actionHtml = onPairs
      ? '<button type="button" class="btn" id="cur-toggle-add-btn">' + (curAddFormOpen ? 'Скрыть форму' : 'Добавить пару') + '</button>'
      : '<button type="button" class="btn" id="cur-add-currency-btn"' + (curCanWriteCurrencies() ? '' : ' hidden') + '>Добавить валюту</button>';
    var bodyHtml = onPairs
      ? '<div class="wallet-search-row"><input type="text" id="cur-search" ' +
        'placeholder="Пара или валюта (например EUR)" value="' + escapeHtml(curQuery) + '"></div>' +
        curAddFormHtml() +
        '<div class="users-table-wrap">' +
        '<table class="users" id="cur-table">' +
        '<thead><tr><th>Пара</th><th>Последний курс</th><th>Изменение</th><th>Действия</th></tr></thead>' +
        '<tbody id="cur-rows"></tbody>' +
        '</table></div>'
      : '<div id="cur-currencies">' + curCurrenciesHtml() + '</div>';
    root.innerHTML =
      '<section class="report-section">' +
      '<div class="cur-tabs-row">' + tabsHtml + actionHtml + '</div>' +
      bodyHtml +
      '</section>';
    if (onPairs) renderCurRows();
  }

  function curRateRowHtml(r, precision) {
    var actionsHtml = r.is_own
      ? '<button type="button" class="link-btn" data-cur-edit-rate="' + escapeHtml(r.date) + '" ' +
        'data-rate="' + escapeHtml(r.rate) + '">Изменить</button> ' +
        '<button type="button" class="link-btn access-danger" data-cur-delete-rate="' +
        escapeHtml(r.date) + '">Удалить</button>'
      : '<span class="sub-id">общий</span>';
    return (
      '<tr>' +
      '<td>' + escapeHtml(formatDate(r.date)) + '</td>' +
      '<td>' + fmtRate(r.rate, precision) + '</td>' +
      '<td>' + actionsHtml + '</td>' +
      '</tr>'
    );
  }

  function curRateFormHtml() {
    if (!curRateFormOpen) return '';
    var editing = curRateFormEditDate !== null;
    var existing = editing ? (curDetailRates || []).filter(function (r) { return r.date === curRateFormEditDate; })[0] : null;
    return (
      '<div class="cur-add-form">' +
      '<input type="date" id="cur-rate-date-input" value="' + escapeHtml(curRateFormEditDate || '') + '"' +
      (editing ? ' disabled' : '') + '>' +
      '<input type="text" id="cur-rate-value-input" placeholder="Курс" ' +
      'value="' + escapeHtml(existing ? existing.rate : '') + '">' +
      '<button type="button" class="btn" id="cur-save-rate-btn">Сохранить</button>' +
      '<button type="button" class="btn btn-secondary" id="cur-cancel-rate-btn">Отмена</button>' +
      '</div>'
    );
  }

  // --- график истории курса (по прямому запросу, 2026-09-11 — "нужен
  // график курсов по примеру андройда, возможность выбора диапазона для
  // отображения через график") -------------------------------------------
  // Android-аналог — RateChartView с двумя перетаскиваемыми "ручками"
  // поверх линии (CurrencyPairRateListActivity.rateChart) — здесь то же
  // самое одним жестом: тащишь по графику, отпускаешь — cur-rate-from/-to
  // (те же поля, что у формы "Применить" выше) выставляются на границы
  // выделения и история перезапрашивается тем же refreshCurDetailRates(),
  // каким её перезапускает сама форма дат.
  var CUR_CHART_W = 640, CUR_CHART_H = 160;

  // rates — тот же массив, что curDetailRates: сервер отдаёт DESC (см.
  // currency_pairs_repo.cpp, ORDER BY date DESC — тот же порядок, что и
  // таблица снизу), графику нужен хронологический порядок слева направо.
  function curRateChartHtml(rates, precision) {
    if (rates.length < 2) {
      return '<p class="sub">Меньше двух курсов в выбранном диапазоне — графику не по чему строить линию.</p>';
    }
    var asc = rates.slice().reverse();
    var vals = asc.map(function (r) { return parseFloat(r.rate); });
    var minV = Math.min.apply(null, vals), maxV = Math.max.apply(null, vals);
    var span = maxV - minV || 1; // все точки равны — не делить на 0, просто прямая посередине
    var padY = 10;
    var stepX = (CUR_CHART_W - 8) / (asc.length - 1);

    var points = asc.map(function (r, i) {
      var norm = (parseFloat(r.rate) - minV) / span; // 0 — минимум окна, 1 — максимум
      return {
        x: 4 + i * stepX,
        y: padY + (1 - norm) * (CUR_CHART_H - padY * 2),
        date: r.date,
        rate: r.rate,
      };
    });

    var polylinePoints = points.map(function (p) { return p.x.toFixed(1) + ',' + p.y.toFixed(1); }).join(' ');
    // Хинт при наведении — тот же wireChartCrosshair, что у столбчатых
    // графиков "Обзора"/"Динамики" (см. ниже, wireCurChart): он ищет
    // БЛИЖАЙШУЮ колонку/точку к курсору через getBoundingClientRect, так что
    // нерегулярная сетка дат (в отличие от фиксированной по месяцам/дням)
    // ему не мешает. <title> (нативная всплывашка с задержкой) больше не
    // нужен — дублировал бы значение из своего хинта.
    var circles = points
      .map(function (p) {
        return '<circle class="cur-chart-point" cx="' + p.x.toFixed(1) + '" cy="' + p.y.toFixed(1) + '" r="2.5"></circle>';
      })
      .join('');

    return (
      '<div class="cur-chart-wrap">' +
      '<div class="cur-chart-plot" id="cur-chart-plot">' +
      '<svg class="cur-chart-svg" id="cur-chart-svg" viewBox="0 0 ' + CUR_CHART_W + ' ' + CUR_CHART_H +
      '" preserveAspectRatio="none">' +
      '<rect class="cur-chart-selection" id="cur-chart-selection" y="0" width="0" height="' + CUR_CHART_H + '" hidden></rect>' +
      '<polyline points="' + polylinePoints + '"></polyline>' +
      circles +
      '</svg>' +
      '</div>' +
      '<div class="cur-chart-axis">' +
      '<span>' + escapeHtml(formatDate(asc[0].date)) + '</span>' +
      '<span class="sub-id">перетащите по графику, чтобы сузить диапазон</span>' +
      '<span>' + escapeHtml(formatDate(asc[asc.length - 1].date)) + '</span>' +
      '</div>' +
      '<div class="cur-chart-minmax">мин ' + escapeHtml(fmtRate(String(minV), precision)) +
      ' · макс ' + escapeHtml(fmtRate(String(maxV), precision)) + '</div>' +
      '</div>'
    );
  }

  // document-уровневые mousemove/mouseup — синглтон на всю жизнь SPA (тот же
  // приём, что currencyPickerOutsideClickWired у пикера валюты эквивалента):
  // renderCurDetail() пересоздаёт #cur-chart-svg на каждый рендер, но эти два
  // слушателя не должны копиться при каждом открытии/обновлении "Курсов
  // валют" — читают текущее состояние из curChartDrag (null — не тащим).
  function wireCurChartDragGlobal() {
    if (curChartDragWired) return;
    curChartDragWired = true;

    document.addEventListener('mousemove', function (ev) {
      if (!curChartDrag) return;
      var rect = curChartDrag.svg.getBoundingClientRect();
      var x1 = (curChartDrag.startX - rect.left) / rect.width * CUR_CHART_W;
      var x2 = (ev.clientX - rect.left) / rect.width * CUR_CHART_W;
      var lo = Math.min(x1, x2), hi = Math.max(x1, x2);
      curChartDrag.selection.setAttribute('x', lo.toFixed(1));
      curChartDrag.selection.setAttribute('width', (hi - lo).toFixed(1));
      curChartDrag.selection.hidden = false;
    });

    document.addEventListener('mouseup', function (ev) {
      if (!curChartDrag) return;
      var drag = curChartDrag;
      curChartDrag = null;
      drag.selection.hidden = true;

      var rect = drag.svg.getBoundingClientRect();
      function xToIndex(clientX) {
        var frac = (clientX - rect.left) / rect.width;
        frac = Math.max(0, Math.min(1, frac));
        return Math.round(frac * (drag.asc.length - 1));
      }
      var i1 = xToIndex(drag.startX), i2 = xToIndex(ev.clientX);
      if (i1 === i2) return; // клик без реального перетаскивания — диапазон не трогаем
      var lo = Math.min(i1, i2), hi = Math.max(i1, i2);
      curRateFrom = drag.asc[lo].date;
      curRateTo = drag.asc[hi].date;
      refreshCurDetailRates(); // тот же путь, что и кнопка "Применить" у полей дат выше
    });
  }

  // mousedown на самом svg — пересоздаётся вместе с ним на каждый
  // renderCurDetail() (тот же приём, что у остальной разметки #cur-root),
  // в отличие от document-уровневых move/up выше (те — синглтон).
  function wireCurChart() {
    wireCurChartDragGlobal();
    var svg = document.getElementById('cur-chart-svg');
    var selection = document.getElementById('cur-chart-selection');
    if (!svg || !selection || !curDetailRates || curDetailRates.length < 2) return;
    var asc = curDetailRates.slice().reverse();

    svg.addEventListener('mousedown', function (ev) {
      var rect = svg.getBoundingClientRect();
      curChartDrag = { svg: svg, selection: selection, asc: asc, startX: ev.clientX };
      selection.setAttribute('x', ((ev.clientX - rect.left) / rect.width * CUR_CHART_W).toFixed(1));
      selection.setAttribute('width', '0');
      selection.hidden = false;
      ev.preventDefault(); // не выделять текст соседних элементов при протяжке
    });

    // Хинт с датой и значением курса под курсором — pair.precision, не 2
    // знака по умолчанию, тот же источник, что и у самих точек графика
    // (curRateChartHtml вызывается с тем же precision из renderCurDetail).
    var pair = (curPairs || []).filter(function (p) { return p.uuid === curDetailPairUuid; })[0];
    var precision = pair ? pair.precision : 2;
    wireChartCrosshair(document.getElementById('cur-chart-plot'), '.cur-chart-point', function (i) {
      var r = asc[i];
      return '<div class="month-chart-tooltip-title">' + escapeHtml(formatDate(r.date)) + '</div>' +
        '<div class="month-chart-tooltip-row"><span>Курс</span><b>' + escapeHtml(fmtRate(r.rate, precision)) + '</b></div>';
    });
  }

  function renderCurDetail() {
    var root = document.getElementById('cur-root');
    if (!root) return;
    var pair = (curPairs || []).filter(function (p) { return p.uuid === curDetailPairUuid; })[0];
    if (!pair) { curDetailPairUuid = null; renderCurRoot(); return; }

    // wallet-currency-flag-lg — тот же .cat-icon, что и в строке списка, но
    // вдвое крупнее (по прямому запросу — "значки слишком маленькие" именно
    // в заголовке открытой пары; строка списка размер не меняет).
    var flags = categoryIconHtml(pair.base_currency.icon_sha256, 'wallet-currency-flag-lg') +
                categoryIconHtml(pair.quote_currency.icon_sha256, 'wallet-currency-flag-lg');
    // .cur-controls-row — тот же класс, что у строки диапазона дат ниже
    // (flex-row с ровными отступами), а не голый <p class="sub"> (там раньше
    // и лежали number-input + 2 кнопки вперемешку с текстом — по прямому
    // запросу, "кривое окно точности").
    var precisionHtml = pair.is_own
      ? '<div class="cur-controls-row">' +
        '<input type="number" id="cur-detail-precision" min="0" max="10" value="' + pair.precision + '" ' +
        'style="width:70px" title="Знаков после запятой">' +
        '<button type="button" class="btn-chip" id="cur-save-precision-btn">Сохранить точность</button>' +
        '<button type="button" class="link-btn access-danger" id="cur-delete-pair-btn">Удалить пару</button>' +
        '</div>'
      : '<p class="sub">Общая пара — точность и удаление недоступны.</p>';

    var rows = (curDetailRates || []).map(function (r) { return curRateRowHtml(r, pair.precision); }).join('');
    var rowsHtml = curDetailRates === null
      ? '<tr><td colspan="3" class="sub">Загрузка…</td></tr>'
      : (rows || '<tr><td colspan="3" class="wallet-empty">Курсов пока нет — добавьте первый.</td></tr>');

    root.innerHTML =
      '<button type="button" class="btn btn-secondary" id="cur-back-btn">← К списку пар</button>' +
      '<section class="report-section">' +
      '<h2>' + flags + ' ' + escapeHtml(pair.symbol) + '</h2>' +
      precisionHtml +
      '<div class="cur-controls-row">' +
      '<input type="date" id="cur-rate-from" value="' + escapeHtml(curRateFrom) + '" title="С даты"> ' +
      '<input type="date" id="cur-rate-to" value="' + escapeHtml(curRateTo) + '" title="По дату"> ' +
      '<button type="button" class="btn btn-secondary" id="cur-apply-range-btn">Применить</button>' +
      '</div>' +
      (curDetailRates === null
        ? '<p class="sub">Загрузка графика…</p>'
        : curRateChartHtml(curDetailRates, pair.precision)) +
      '<button type="button" class="btn" id="cur-toggle-rate-form-btn">' +
      (curRateFormOpen ? 'Скрыть форму' : 'Добавить курс') + '</button>' +
      curRateFormHtml() +
      '<div class="users-table-wrap">' +
      '<table class="users"><thead><tr><th>Дата</th><th>Курс</th><th>Действия</th></tr></thead>' +
      '<tbody id="cur-rate-rows">' + rowsHtml + '</tbody></table></div>' +
      '</section>';

    wireCurChart();
  }

  function renderCurRoot() {
    if (curDetailPairUuid) renderCurDetail();
    else renderCurList();
  }

  function refreshCurrencyPairs() {
    var root = document.getElementById('cur-root');
    if (root) root.innerHTML = '<p class="sub">Загрузка…</p>';
    apiJson('/api/currency-pairs', { credentials: 'include' })
      .then(function (data) {
        if (!data) return; // 401 — renderLogin() уже вызван
        curPairs = data.pairs;
        renderCurRoot();
      })
      .catch(function (err) {
        if (root) root.innerHTML = reportsErrorHtml('Не удалось загрузить валютные пары: ' + err.message);
      });
  }

  function refreshCurDetailRates() {
    curDetailRates = null;
    renderCurDetail();
    var query = [];
    if (curRateFrom) query.push('from=' + encodeURIComponent(curRateFrom));
    if (curRateTo) query.push('to=' + encodeURIComponent(curRateTo));
    var url = '/api/currency-pairs/' + encodeURIComponent(curDetailPairUuid) + '/rates' +
      (query.length ? '?' + query.join('&') : '');
    apiJson(url, { credentials: 'include' })
      .then(function (data) {
        if (!data) return;
        curDetailRates = data.rates;
        renderCurDetail();
      })
      .catch(function (err) {
        var tbody = document.getElementById('cur-rate-rows');
        if (tbody) tbody.innerHTML = '<tr><td colspan="3" class="err">' + escapeHtml(err.message) + '</td></tr>';
      });
  }

  function openCurDetail(pairUuid) {
    curDetailPairUuid = pairUuid;
    curDetailRates = null;
    curRateFormOpen = false;
    curRateFormEditDate = null;
    curRateFrom = '';
    curRateTo = '';
    renderCurDetail();
    refreshCurDetailRates();
  }

  function wireCurEvents() {
    var root = document.getElementById('cur-root');
    if (!root) return;

    // Поиск — отдельно от делегирующего click-слушателя ниже: input этого
    // элемента переживает renderCurRows() (та трогает только #cur-rows, не
    // #cur-search сам), но НЕ переживает renderCurList()/renderCurDetail()
    // (пересоздают весь #cur-root) — слушаем через делегирование на root
    // ('input' тоже всплывает), не на сам #cur-search: он может быть уже
    // другим DOM-узлом к моменту следующего renderCurList().
    root.addEventListener('input', function (ev) {
      if (ev.target.id === 'cur-search') {
        curQuery = ev.target.value;
        renderCurRows();
      }
    });

    root.addEventListener('click', function (ev) {
      var el;

      if ((el = ev.target.closest('#cur-toggle-add-btn'))) {
        curAddFormOpen = !curAddFormOpen;
        curBaseUuid = ''; curQuoteUuid = ''; curPairPickerOpen = null; // тот же дефолт, что был у пустых <option>
        renderCurList();
        return;
      }
      if (ev.target.closest('#cur-cancel-add-btn')) {
        curAddFormOpen = false;
        curPairPickerOpen = null;
        renderCurList();
        return;
      }
      // Вкладки "Валютные пары" / "Справочник валют" (currency-form-ux D1).
      if ((el = ev.target.closest('[data-cur-tab]'))) {
        var tab = el.getAttribute('data-cur-tab');
        if (tab !== curTab) {
          curTab = tab;
          curPairPickerOpen = null;
          curCurrenciesError = '';
          renderCurList();
        }
        return;
      }
      if (ev.target.closest('#cur-add-currency-btn')) {
        openCurCurrencyForm(null);
        return;
      }
      if ((el = ev.target.closest('[data-cur-edit-currency]'))) {
        var editUuid = el.getAttribute('data-cur-edit-currency');
        var editCur = currencyDirectory.filter(function (c) { return c.uuid === editUuid; })[0];
        if (editCur) openCurCurrencyForm(editCur);
        return;
      }
      if ((el = ev.target.closest('[data-cur-delete-currency]'))) {
        var delUuid = el.getAttribute('data-cur-delete-currency');
        curCurrenciesError = '';
        if (!window.confirm('Удалить валюту ' + el.getAttribute('data-iso') + '?')) { renderCurCurrencies(); return; }
        el.disabled = true;
        apiJson('/api/currencies/' + encodeURIComponent(delUuid), { method: 'DELETE', credentials: 'include' })
          .then(function (res) {
            if (!res) { el.disabled = false; return; }
            afterCurrencyWrite();
          })
          .catch(function (err) {
            // Без alert (D6) — строкой над таблицей до следующего действия.
            curCurrenciesError = 'Не удалось удалить валюту: ' + currencyErrorText(err);
            renderCurCurrencies();
          });
        return;
      }
      // Флаговые пикеры формы "Добавить пару" — кнопка открывает/закрывает
      // ("тот же", что уже открыт, — закрывает; другой — переключает на
      // себя, оба разом открытыми быть не могут), строка внутри списка
      // выбирает валюту и закрывает список.
      if ((el = ev.target.closest('[data-pair-toggle]'))) {
        var toggleKind = el.getAttribute('data-pair-toggle');
        curPairPickerOpen = curPairPickerOpen === toggleKind ? null : toggleKind;
        renderCurList();
        return;
      }
      if ((el = ev.target.closest('[data-pair-pick]'))) {
        var pickKind = el.getAttribute('data-pair-pick');
        var pickUuid = el.getAttribute('data-uuid');
        if (pickKind === 'base') curBaseUuid = pickUuid; else curQuoteUuid = pickUuid;
        curPairPickerOpen = null;
        renderCurList();
        return;
      }
      if ((el = ev.target.closest('#cur-create-pair-btn'))) {
        var base = document.getElementById('cur-base-select').value;
        var quote = document.getElementById('cur-quote-select').value;
        var precision = parseInt(document.getElementById('cur-precision-input').value, 10);
        if (!base || !quote) { window.alert('Выберите обе валюты'); return; }
        if (base === quote) { window.alert('Валюты должны различаться'); return; }
        el.disabled = true;
        apiJson('/api/currency-pairs', {
          method: 'POST',
          credentials: 'include',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ base_currency_uuid: base, quote_currency_uuid: quote,
            precision: isNaN(precision) ? 5 : precision }),
        })
          .then(function (created) {
            if (!created) return;
            curAddFormOpen = false;
            refreshCurrencyPairs();
          })
          .catch(function (err) { window.alert('Не удалось создать пару: ' + err.message); el.disabled = false; });
        return;
      }
      if ((el = ev.target.closest('[data-cur-delete-pair]'))) {
        var pairUuid = el.getAttribute('data-cur-delete-pair');
        var symbol = el.getAttribute('data-symbol');
        if (!window.confirm('Удалить пару ' + symbol + '? Вся история её курса тоже будет удалена.')) return;
        el.disabled = true;
        apiJson('/api/currency-pairs/' + encodeURIComponent(pairUuid), { method: 'DELETE', credentials: 'include' })
          .then(function (res) { if (res) refreshCurrencyPairs(); else el.disabled = false; })
          .catch(function (err) { window.alert('Не удалось удалить пару: ' + err.message); el.disabled = false; });
        return;
      }
      if ((el = ev.target.closest('[data-cur-open]'))) {
        openCurDetail(el.getAttribute('data-cur-open'));
        return;
      }
      if (ev.target.closest('#cur-back-btn')) {
        curDetailPairUuid = null;
        renderCurList();
        return;
      }
      if ((el = ev.target.closest('#cur-save-precision-btn'))) {
        var newPrecision = parseInt(document.getElementById('cur-detail-precision').value, 10);
        el.disabled = true;
        apiJson('/api/currency-pairs/' + encodeURIComponent(curDetailPairUuid), {
          method: 'PATCH',
          credentials: 'include',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ precision: isNaN(newPrecision) ? 5 : newPrecision }),
        })
          .then(function (updated) {
            if (!updated) return;
            curPairs = curPairs.map(function (p) { return p.uuid === updated.uuid ? updated : p; });
            renderCurDetail();
          })
          .catch(function (err) { window.alert('Не удалось изменить точность: ' + err.message); el.disabled = false; });
        return;
      }
      if (ev.target.closest('#cur-delete-pair-btn')) {
        var pair = curPairs.filter(function (p) { return p.uuid === curDetailPairUuid; })[0];
        if (!window.confirm('Удалить пару ' + (pair ? pair.symbol : '') +
            '? Вся история её курса тоже будет удалена.')) return;
        apiJson('/api/currency-pairs/' + encodeURIComponent(curDetailPairUuid),
          { method: 'DELETE', credentials: 'include' })
          .then(function (res) {
            if (!res) return;
            curDetailPairUuid = null;
            refreshCurrencyPairs();
          })
          .catch(function (err) { window.alert('Не удалось удалить пару: ' + err.message); });
        return;
      }
      if (ev.target.closest('#cur-apply-range-btn')) {
        curRateFrom = document.getElementById('cur-rate-from').value;
        curRateTo = document.getElementById('cur-rate-to').value;
        refreshCurDetailRates();
        return;
      }
      if ((el = ev.target.closest('#cur-toggle-rate-form-btn'))) {
        curRateFormOpen = !curRateFormOpen;
        curRateFormEditDate = null;
        renderCurDetail();
        return;
      }
      if (ev.target.closest('#cur-cancel-rate-btn')) {
        curRateFormOpen = false;
        curRateFormEditDate = null;
        renderCurDetail();
        return;
      }
      if ((el = ev.target.closest('[data-cur-edit-rate]'))) {
        curRateFormOpen = true;
        curRateFormEditDate = el.getAttribute('data-cur-edit-rate');
        renderCurDetail();
        return;
      }
      if ((el = ev.target.closest('[data-cur-delete-rate]'))) {
        var rateDate = el.getAttribute('data-cur-delete-rate');
        if (!window.confirm('Удалить курс на ' + rateDate + '?')) return;
        el.disabled = true;
        apiJson('/api/currency-pairs/' + encodeURIComponent(curDetailPairUuid) + '/rates/' + rateDate,
          { method: 'DELETE', credentials: 'include' })
          .then(function (res) { if (res) refreshCurDetailRates(); else el.disabled = false; })
          .catch(function (err) { window.alert('Не удалось удалить курс: ' + err.message); el.disabled = false; });
        return;
      }
      if ((el = ev.target.closest('#cur-save-rate-btn'))) {
        var date = document.getElementById('cur-rate-date-input').value;
        var rateValue = document.getElementById('cur-rate-value-input').value.trim().replace(',', '.');
        if (!date || !rateValue) { window.alert('Заполните дату и курс'); return; }
        el.disabled = true;
        apiJson('/api/currency-pairs/' + encodeURIComponent(curDetailPairUuid) + '/rates', {
          method: 'POST',
          credentials: 'include',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ date: date, rate: rateValue }),
        })
          .then(function (res) {
            if (!res) return;
            curRateFormOpen = false;
            curRateFormEditDate = null;
            refreshCurDetailRates();
          })
          .catch(function (err) { window.alert('Не удалось сохранить курс: ' + err.message); el.disabled = false; });
        return;
      }

      // Дошли до конца — клик не попал ни в один известный элемент (в т.ч.
      // не в сам флаговый пикер и не в его список, у обоих branch выше уже
      // return'нулся бы) — закрываем открытый пикер, если он есть, тем же
      // приёмом "клик мимо", что currencyPickerOutsideClickWired у пикера
      // валюты эквивалента, но проще: этот делегирован на #cur-root, а не
      // на document, так что срабатывает уже только на клики внутри формы.
      if (curPairPickerOpen !== null) {
        curPairPickerOpen = null;
        renderCurList();
      }
    });

    wireCurCurrencyDialog();
  }

  // Окно формы валюты (currency-form-ux D2) — вне #cur-root, поэтому свои
  // делегирующие слушатели на самом <dialog>; узел живёт, пока открыты
  // "Отчёты", его содержимое перерисовывает renderCurCurrencyDialog().
  function wireCurCurrencyDialog() {
    var dlg = curDialogEl();
    if (!dlg) return;

    // Esc: нативный cancel закрыл бы окно, но не сбросил бы форму.
    dlg.addEventListener('cancel', function (ev) {
      ev.preventDefault();
      closeCurCurrencyDialog();
    });

    dlg.addEventListener('input', function (ev) {
      var f = curCurrencyForm;
      var t = ev.target;
      if (!f) return;
      if (t.id === 'cur-icon-search') {
        curIconQuery = t.value;
        renderCurIconGrid();
        return;
      }
      var key = { 'cur-currency-iso': 'iso_code', 'cur-currency-name': 'name',
                  'cur-currency-symbol': 'symbol', 'cur-currency-precision': 'precision' }[t.id];
      if (!key) return;
      if (key === 'iso_code') {
        // Верхний регистр на лету (D7) с сохранением позиции курсора.
        var upper = t.value.toUpperCase();
        if (upper !== t.value) {
          var pos = t.selectionStart;
          t.value = upper;
          t.setSelectionRange(pos, pos);
        }
        curUpdateSymbolPlaceholder();
      }
      f[key] = t.value;
      delete f.auto[key]; // набрано руками — каталог это поле больше не трогает
      if (f.errors[key]) { f.errors[key] = ''; curRenderFieldError(key); }
      if (key === 'iso_code') curApplyPreset(curPresetByIso(t.value), 'iso_code');
      if (key === 'name') curApplyPreset(curPresetByName(t.value), 'name');
    });

    dlg.addEventListener('change', function (ev) {
      if (ev.target.id === 'cur-currency-eq' && curCurrencyForm) curCurrencyForm.show_in_equivalent = ev.target.checked;
    });

    // Enter в поле поиска флага не должен отправлять форму method="dialog".
    dlg.addEventListener('submit', function (ev) { ev.preventDefault(); });

    dlg.addEventListener('click', function (ev) {
      var el;
      var f = curCurrencyForm;
      // Клик по самому <dialog> (не по .cur-dialog-body) — по затемнению вокруг окна.
      if (ev.target === dlg) { closeCurCurrencyDialog(); return; }
      if (!f) return;
      if (ev.target.closest('#cur-cancel-currency-btn')) { closeCurCurrencyDialog(); return; }
      if (ev.target.closest('#cur-currency-icon-btn')) {
        curCurrencyIconPickerOpen = !curCurrencyIconPickerOpen;
        renderCurCurrencyIconPicker();
        var search = document.getElementById('cur-icon-search');
        if (search) search.focus();
        return;
      }
      if ((el = ev.target.closest('[data-cur-pick-icon]'))) {
        f.icon_uuid = el.getAttribute('data-cur-pick-icon');
        f.icon_sha256 = el.getAttribute('data-sha256');
        delete f.auto.icon; // выбран руками — пресет его не заменит
        f.errors.icon = '';
        curCurrencyIconPickerOpen = false;
        curIconQuery = '';
        renderCurCurrencyIconPicker();
        return;
      }
      if ((el = ev.target.closest('#cur-save-currency-btn'))) {
        var curName = document.getElementById('cur-currency-name').value.trim();
        var curIso = document.getElementById('cur-currency-iso').value.trim().toUpperCase();
        var curSymbol = document.getElementById('cur-currency-symbol').value.trim();
        var curPrecision = parseInt(document.getElementById('cur-currency-precision').value, 10);
        // Клиентские проверки (D6) — все сразу, без alert и без запроса.
        f.errors = {
          name: curName ? '' : 'Заполните название',
          iso_code: curIso ? '' : 'Заполните ISO-код',
          icon: f.icon_uuid ? '' : 'Выберите иконку',
          form: '',
        };
        ['name', 'iso_code', 'icon', 'form'].forEach(curRenderFieldError);
        if (f.errors.name || f.errors.iso_code || f.errors.icon) {
          var bad = document.querySelector('#cur-currency-dialog .invalid');
          if (bad && bad.focus) bad.focus();
          return;
        }
        var curBody = {
          name: curName,
          iso_code: curIso,
          icon_uuid: f.icon_uuid,
          precision: isNaN(curPrecision) ? 2 : curPrecision,
          show_in_equivalent: document.getElementById('cur-currency-eq').checked,
        };
        if (curSymbol) curBody.symbol = curSymbol; // пустой — не отправляем: сервер подставит ISO-код (новая) / не тронет (правка)
        el.disabled = true;
        apiJson(f.uuid ? '/api/currencies/' + encodeURIComponent(f.uuid) : '/api/currencies', {
          method: f.uuid ? 'PATCH' : 'POST',
          credentials: 'include',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(curBody),
        })
          .then(function (saved) {
            if (!saved) return; // 401 — renderLogin() уже вызван
            closeCurCurrencyDialog();
            afterCurrencyWrite();
          })
          .catch(function (err) {
            // Окно могли закрыть, пока шёл запрос, — тогда показывать некуда.
            if (curCurrencyForm !== f) return;
            el.disabled = false; // форма остаётся открытой с введёнными значениями
            var b = err && err.body;
            var dupField = b && b.error === 'duplicate' && (b.field === 'iso_code' || b.field === 'name') ? b.field : null;
            if (dupField) {
              f.errors[dupField] = currencyErrorText(err);
              curRenderFieldError(dupField);
              var dupEl = document.getElementById(CUR_FIELD_IDS[dupField]);
              if (dupEl) dupEl.focus();
            } else {
              f.errors.form = 'Не удалось сохранить валюту: ' + currencyErrorText(err);
              curRenderFieldError('form');
            }
          });
        return;
      }
    });
  }

  // --- «ИИ» (view 'ai', add-ai-expense-text) -------------------------------
  // Пункт виден только по ответу GET /api/ai/status (wallet-ai): enabled и
  // в features есть parse_expense или statement_import; разделы экрана — по
  // своим features (add-ai-statement-import). Статус — один раз при открытии "Отчётов", вне
  // refreshPeriod (как refreshCurrencyPairs): от периода он не зависит, а
  // остальные вкладки его не ждут. В режиме "Посмотреть как клиент" пункт
  // скрыт всегда — запись ушла бы в кошелёк администратора, не клиента.
  //
  // aiStatus: null — ответа ещё нет, true/false — пункт показан/скрыт.
  // aiRestorePending — F5 пришёл на #/reports/ai раньше ответа статуса:
  // пока показан "Обзор", а когда статус придёт включённым — переключаемся
  // на "ИИ", если пользователь за это время никуда не ушёл сам.
  var aiStatus = null;
  var aiFeatures = []; // features из /api/ai/status, см. aiHas
  var aiRestorePending = false;

  function setAiNavVisible(visible) {
    var group = document.getElementById('nav-group-ai');
    if (group) group.hidden = !visible;
  }

  function refreshAiStatus() {
    aiStatus = null;
    aiFeatures = [];
    aiRestorePending = false; // просьбу восстановить "ИИ" ставит уже следующий switchReportsView (F5/popstate)
    setAiNavVisible(false);
    if (viewAsUser) {
      aiStatus = false;
      chatSetAvailable(false); // ответы шли бы по кошельку администратора
      return;
    }
    apiFetch('/api/ai/status', { credentials: 'include' })
      .then(function (res) {
        if (!res.ok) return null; // 401/403/5xx — пункт просто скрыт, сессией займутся другие запросы
        return res.json();
      })
      .then(function (data) {
        var ok = !!data && data.enabled === true && Array.isArray(data.features);
        // Чат — отдельно от пункта «ИИ» (add-web-chat, D5): только chat в
        // features не должен показывать пустой пункт меню.
        chatSetAvailable(ok && data.features.indexOf('chat') >= 0);
        if (!ok) return [];
        return data.features.filter(function (f) { return f === 'parse_expense' || f === 'statement_import'; });
      }, function () {
        chatSetAvailable(false);
        return [];
      })
      .then(function (features) {
        if (!document.getElementById('nav-group-ai')) return; // "Отчёты" уже закрыты
        var enabled = features.length > 0;
        aiStatus = enabled;
        aiFeatures = features;
        setAiNavVisible(enabled);
        renderAiRoot();
        stOnStatus();
        if (enabled && aiRestorePending && reportsView === 'over') {
          isApplyingHistoryState = true;
          switchReportsView('ai');
          isApplyingHistoryState = false;
          replaceReportsUrlState('ai');
        }
        aiRestorePending = false;
      });
  }

  // --- «Справка» (view 'docs', docs-assistant) ------------------------------
  // Вопрос своими словами → POST /api/docs/ask (wallet-docs через гейтвей) →
  // ответ текстом и «Источники». Пункт — по образцу «ИИ» (D1): виден только
  // при 200 на GET /api/docs/status, статус один раз при открытии «Отчётов»,
  // в режиме «Посмотреть как клиент» не запрашивается (D5) — токен
  // администраторский, ответ показал бы всю систему под видом клиента.
  // Область документации выбирает сервер по role/platform токена; клиент о
  // себе ничего не сообщает.
  //
  // docsStatus: null — ответа ещё нет, true/false — пункт показан/скрыт.
  // docsRestorePending — то же, что aiRestorePending: F5 на #/reports/docs
  // раньше ответа статуса.
  // Вопрос и ответ живут только здесь, в памяти: уход с экрана (docsReset из
  // switchReportsView), закрытие «Отчётов» и F5 их стирают — так по спеке.
  var DOCS_QUESTION_MAX = 1000;
  var docsStatus = null;
  var docsRestorePending = false;
  var docsQuestion = '';
  var docsBusy = false;
  var docsAttempt = 0; // токен запроса: ответ после ухода с экрана выбрасывается
  var docsResult = null; // { answer, sources } из POST /api/docs/ask
  var docsError = '';

  function setDocsNavVisible(visible) {
    var group = document.getElementById('nav-group-docs');
    if (group) group.hidden = !visible;
  }

  function refreshDocsStatus() {
    docsStatus = null;
    docsRestorePending = false;
    setDocsNavVisible(false);
    if (viewAsUser) {
      docsStatus = false;
      return;
    }
    apiFetch('/api/docs/status', { credentials: 'include' })
      .then(function (res) {
        // 404 — wallet-docs не подключён к гейтвею, 401/403/5xx — недоступен
        // этому пользователю. Повторов нет (D2): до следующего открытия «Отчётов».
        if (res.status !== 200) return null;
        return res.json().catch(function () { return null; });
      }, function () {
        return null; // сеть
      })
      .then(function (data) {
        if (!document.getElementById('nav-group-docs')) return; // «Отчёты» уже закрыты
        var enabled = !!data && data.enabled === true;
        docsStatus = enabled;
        setDocsNavVisible(enabled);
        if (enabled && docsRestorePending && reportsView === 'over') {
          isApplyingHistoryState = true;
          switchReportsView('docs');
          isApplyingHistoryState = false;
          replaceReportsUrlState('docs');
        }
        docsRestorePending = false;
      });
  }

  // Ушли с экрана — вопрос, ответ и запрос в полёте забываются.
  function docsReset() {
    docsAttempt++;
    docsQuestion = '';
    docsBusy = false;
    docsResult = null;
    docsError = '';
    renderDocsRoot();
  }

  // Подпись источника (D4): роль — подсказка отображения, доступ к спекам
  // решает сервер. У администратора область — вся система, поэтому имя
  // репозитория нужно; остальным оно ничего не скажет. Повторы (несколько
  // фрагментов одного раздела) схлопываются, порядок — как у сервера.
  function docsSourceLines(sources) {
    var isAdmin = !!currentUser && currentUser.role === 'admin';
    var seen = {};
    var lines = [];
    (sources || []).forEach(function (s) {
      if (!s || !s.capability) return;
      var line = isAdmin && s.repo ? s.repo + ' · ' + s.capability : s.capability;
      if (seen[line]) return;
      seen[line] = true;
      lines.push(line);
    });
    return lines;
  }

  // --- Markdown ответа «Справки» (D3) ---------------------------------------
  // Небольшое подмножество, которое пишет LLM: заголовки, абзацы, **жирный**,
  // *курсив*, `код`, ```блоки```, списки -/*/+ и 1., цитаты >, таблицы |…|,
  // разделитель ---, ссылки [текст](http…). Правило безопасности одно: любой
  // кусок исходного текста попадает в HTML только через escapeHtml, теги
  // ставит сам рендерер. Поэтому <img onerror> из индекса остаётся текстом, а
  // ссылка — только на http(s) (javascript: и прочее — просто текст).
  // Вложенные списки уплощаются: для коротких ответов этого достаточно.
  var DOCS_CODE_OPEN = ''; // символы личного пользования — в ответе их не бывает
  var DOCS_CODE_CLOSE = '';

  function docsInlineHtml(text) {
    var codes = [];
    var s = text.replace(/`([^`\n]+)`/g, function (_, code) {
      codes.push('<code>' + escapeHtml(code) + '</code>');
      return DOCS_CODE_OPEN + (codes.length - 1) + DOCS_CODE_CLOSE;
    });
    s = escapeHtml(s);
    s = s.replace(/\[([^\]\n]+)\]\((https?:\/\/[^\s)]+)\)/g, function (_, label, url) {
      return '<a href="' + url.replace(/"/g, '&quot;') + '" target="_blank" rel="noopener noreferrer">' + label + '</a>';
    });
    s = s.replace(/\*\*([^*\n]+?)\*\*/g, '<strong>$1</strong>');
    // __жирный__ — только на границе слова: иначе ловит идентификаторы (window.__x … y.__z).
    s = s.replace(/(^|[^\w])__(?!\s)([^_\n]+?)__(?!\w)/g, '$1<strong>$2</strong>');
    // *курсив*: не внутри слова и не «* » (маркер списка разобран раньше).
    s = s.replace(/(^|[^*\w])\*(?!\s)([^*\n]+?)\*(?![*\w])/g, '$1<em>$2</em>');
    return s.replace(new RegExp(DOCS_CODE_OPEN + '(\\d+)' + DOCS_CODE_CLOSE, 'g'), function (_, i) {
      return codes[+i];
    });
  }

  function docsTableCells(line) {
    return line.trim().replace(/^\|/, '').replace(/\|$/, '').split('|').map(function (c) { return c.trim(); });
  }

  function docsMarkdownHtml(md) {
    var lines = String(md).replace(/\r\n?/g, '\n').split('\n');
    var out = [];
    var para = [];
    var quote = [];
    var list = null; // { tag: 'ul'|'ol', items: [] }
    function flushPara() {
      if (para.length) out.push('<p>' + para.map(docsInlineHtml).join('<br>') + '</p>');
      para = [];
    }
    function flushQuote() {
      if (quote.length) out.push('<blockquote>' + quote.map(docsInlineHtml).join('<br>') + '</blockquote>');
      quote = [];
    }
    function flushList() {
      if (list) {
        out.push('<' + list.tag + '>' + list.items.map(function (it) {
          return '<li>' + docsInlineHtml(it) + '</li>';
        }).join('') + '</' + list.tag + '>');
      }
      list = null;
    }
    function flushAll() { flushPara(); flushQuote(); flushList(); }
    // Старший уровень заголовка в ответе станет h3 (h1/h2 заняты шапкой
    // страницы): LLM часто начинает с «##», и без сдвига всё было бы мельче.
    var topLevel = 6;
    lines.forEach(function (l) {
      var hm = /^\s{0,3}(#{1,6})\s/.exec(l);
      if (hm && hm[1].length < topLevel) topLevel = hm[1].length;
    });
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      var m;
      if (/^\s*```/.test(line)) {
        flushAll();
        var code = [];
        for (i++; i < lines.length && !/^\s*```/.test(lines[i]); i++) code.push(lines[i]);
        out.push('<pre><code>' + escapeHtml(code.join('\n')) + '</code></pre>');
        continue;
      }
      if (!line.trim()) { flushAll(); continue; }
      if ((m = /^\s{0,3}(#{1,6})\s+(.*?)\s*#*\s*$/.exec(line))) {
        flushAll();
        var h = Math.min(m[1].length - topLevel + 3, 6);
        out.push('<h' + h + '>' + docsInlineHtml(m[2]) + '</h' + h + '>');
        continue;
      }
      if (/^\s{0,3}([-*_])(\s*\1){2,}\s*$/.test(line)) { flushAll(); out.push('<hr>'); continue; }
      // Таблица: строка с | и следующая — разделитель |---|:--:|.
      if (line.indexOf('|') >= 0 && i + 1 < lines.length &&
          /^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$/.test(lines[i + 1])) {
        flushAll();
        var head = docsTableCells(line);
        var rows = [];
        for (i += 2; i < lines.length && lines[i].indexOf('|') >= 0 && lines[i].trim(); i++) rows.push(docsTableCells(lines[i]));
        i--;
        out.push('<div class="docs-table-wrap"><table><thead><tr>' +
          head.map(function (c) { return '<th>' + docsInlineHtml(c) + '</th>'; }).join('') + '</tr></thead><tbody>' +
          rows.map(function (r) {
            return '<tr>' + r.map(function (c) { return '<td>' + docsInlineHtml(c) + '</td>'; }).join('') + '</tr>';
          }).join('') + '</tbody></table></div>');
        continue;
      }
      if ((m = /^\s*>\s?(.*)$/.exec(line))) { flushPara(); flushList(); quote.push(m[1]); continue; }
      if ((m = /^\s*([-*+]|\d+[.)])\s+(.*)$/.exec(line))) {
        flushPara(); flushQuote();
        var tag = /\d/.test(m[1]) ? 'ol' : 'ul';
        if (!list || list.tag !== tag) { flushList(); list = { tag: tag, items: [] }; }
        list.items.push(m[2]);
        continue;
      }
      // Продолжение пункта списка — строка с отступом сразу под ним.
      if (list && /^\s{2,}\S/.test(line)) { list.items[list.items.length - 1] += ' ' + line.trim(); continue; }
      flushQuote(); flushList();
      para.push(line.trim());
    }
    flushAll();
    return out.join('');
  }

  // Форма рисуется один раз за заход на экран, дальше меняется только
  // #docs-result и доступность кнопки — фокус и курсор в поле не теряются.
  function renderDocsRoot() {
    var root = document.getElementById('docs-root');
    if (!root) return;
    root.innerHTML =
      '<section class="report-section ai-input docs-ask">' +
      '<textarea id="docs-question" rows="3" maxlength="' + DOCS_QUESTION_MAX + '" ' +
      'placeholder="Ваш вопрос…" aria-label="Ваш вопрос">' + escapeHtml(docsQuestion) + '</textarea>' +
      '<div class="ai-input-row">' +
      '<span class="ai-counter">Ctrl+Enter — спросить</span>' +
      '<button type="button" class="btn" id="docs-ask-btn">Спросить</button>' +
      '</div>' +
      '<div id="docs-result" aria-live="polite"></div>' +
      '</section>';
    var textEl = document.getElementById('docs-question');
    textEl.addEventListener('input', function () {
      docsQuestion = textEl.value;
      docsUpdateButton();
    });
    // Enter — перенос строки (вопрос бывает в несколько строк), Ctrl/⌘+Enter — отправить.
    textEl.addEventListener('keydown', function (ev) {
      if (ev.key === 'Enter' && (ev.ctrlKey || ev.metaKey) && !ev.isComposing) {
        ev.preventDefault();
        docsAsk();
      }
    });
    document.getElementById('docs-ask-btn').addEventListener('click', docsAsk);
    docsUpdateButton();
    renderDocsResult();
  }

  function docsUpdateButton() {
    var btn = document.getElementById('docs-ask-btn');
    if (btn) btn.disabled = docsBusy || !docsQuestion.trim();
  }

  // Ответ — через docsMarkdownHtml, сообщения — через textContent/escapeHtml
  // (D3): HTML из индекса спек и сам вопрос не должны исполниться.
  function renderDocsResult() {
    var box = document.getElementById('docs-result');
    if (!box) return;
    if (docsBusy) {
      box.innerHTML = '<div class="ai-status"><span class="ai-spinner" aria-hidden="true"></span>Ищу ответ…</div>';
      return;
    }
    if (docsError) {
      box.innerHTML = '<div class="ai-status ai-status-fail" role="alert"></div>';
      box.firstChild.textContent = docsError;
      return;
    }
    if (!docsResult) {
      box.innerHTML = '';
      return;
    }
    var lines = docsSourceLines(docsResult.sources);
    box.innerHTML =
      '<div class="docs-answer">' +
      '<div class="docs-answer-text" id="docs-answer-text">' + docsMarkdownHtml(docsResult.answer) + '</div>' +
      (lines.length
        ? '<div class="docs-sources"><div class="docs-sources-label">Источники</div><ul>' +
          lines.map(function (l) { return '<li>' + escapeHtml(l) + '</li>'; }).join('') +
          '</ul></div>'
        : '') +
      '</div>';
  }

  // Текст ошибки по ответу сервиса. 401 сюда приходит уже после попытки
  // тихого /auth/refresh в apiFetch; на экран входа не уводим — вопрос
  // должен остаться в поле.
  function docsErrorMessage(status, data) {
    if (status === 401) return 'Сессия истекла, войдите заново';
    if (status === 400) return (data && data.error) || 'Неверный вопрос';
    if (status === 429) return 'Слишком много вопросов подряд. Подождите минуту.';
    return 'Сервис ответов недоступен'; // 404/502/503 и всё прочее
  }

  function docsAsk() {
    var question = docsQuestion.trim();
    if (docsBusy || !question) return;
    var attempt = ++docsAttempt;
    docsBusy = true;
    docsError = '';
    docsResult = null;
    docsUpdateButton();
    renderDocsResult();
    function finish(result, error) {
      if (attempt !== docsAttempt) return; // ушли с экрана или закрыли «Отчёты»
      docsBusy = false;
      docsResult = result;
      docsError = error;
      docsUpdateButton();
      renderDocsResult();
    }
    apiFetch('/api/docs/ask', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ question: question }),
    }).then(function (res) {
      return res.json().catch(function () { return null; }).then(function (data) {
        if (res.status === 200 && data && typeof data.answer === 'string') {
          finish({ answer: data.answer, sources: Array.isArray(data.sources) ? data.sources : [] }, '');
        } else {
          finish(null, docsErrorMessage(res.status === 200 ? 502 : res.status, data));
        }
      });
    }, function () {
      finish(null, 'Нет связи. Попробуйте позже.');
    });
  }

  // --- «ИИ» → «Трата своими словами» ---------------------------------------
  // Текст → задание parse_expense в wallet-ai → карточка черновика → запись
  // операции в wallet-api (POST /sync/push), тем же путём, что телефон и бот.
  // ИИ сам ничего не пишет: запись — только по кнопке "Записать". Если ИИ не
  // справился — та же карточка, заполненная вручную.
  //
  // aiPhase: 'input' — поле ввода (под ним, может быть, "Записано: …" или
  // причина отказа ИИ), 'parsing' — ждём задание, 'card' — карточка.
  // aiAttempt — токен попытки: каждый старт и каждая отмена его увеличивают,
  // ответ устаревшей попытки (отменённой, ушли с вкладки, закрыли "Отчёты")
  // выбрасывается, а не рисуется поверх текущего экрана.
  var AI_TEXT_MAX = 500;
  var AI_LAST_WALLET_KEY = 'aiLastWalletUuid';
  var aiPhase = 'input';
  var aiText = '';
  var aiAttempt = 0;
  var aiJobId = null;
  var aiFailure = null; // { message } — причина, почему черновика нет; под ней "Заполнить вручную"
  var aiDoneLine = ''; // "Записано: …" после успешной записи
  var aiCard = null; // см. aiNewCard
  var aiAccounts = null; // { wallets, categories } из GET /api/reports/accounts

  // UUID v4 через crypto.getRandomValues, не crypto.randomUUID: веб открывают
  // по http в LAN, а там randomUUID нет (не secure context).
  function uuidV4() {
    var b = crypto.getRandomValues(new Uint8Array(16));
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    var h = Array.prototype.map.call(b, function (x) { return (x < 16 ? '0' : '') + x.toString(16); }).join('');
    return h.slice(0, 8) + '-' + h.slice(8, 12) + '-' + h.slice(12, 16) + '-' + h.slice(16, 20) + '-' + h.slice(20);
  }

  function pad2(n) { return (n < 10 ? '0' : '') + n; }

  function localTime(d) {
    return pad2(d.getHours()) + ':' + pad2(d.getMinutes()) + ':' + pad2(d.getSeconds());
  }

  // Последний кошелёк, с которого записали трату в этом браузере, — уходит в
  // default_wallet_uuid задания (у бота для этого /default). try/catch —
  // приватный режим/заблокированное хранилище просто теряют подсказку.
  function getAiLastWallet() {
    try {
      return localStorage.getItem(AI_LAST_WALLET_KEY) || '';
    } catch (e) {
      return '';
    }
  }

  function setAiLastWallet(uuid) {
    try {
      localStorage.setItem(AI_LAST_WALLET_KEY, uuid);
    } catch (e) {
      // не запомнили — в следующий раз ИИ просто не получит подсказку
    }
  }

  // Ответ "ИИ" дошёл, а "Отчёты" уже закрыты или пользователь на другой
  // попытке — такой ответ никуда не рисуется.
  function aiAttemptAlive(attempt) {
    return attempt === aiAttempt && !!document.getElementById('ai-root');
  }

  // Сброс при каждом заходе на "Отчёты" (renderReports): незавершённое
  // задание прошлого захода отменяется, карточка и текст не переживают ухода.
  function resetAi() {
    aiCancelParsing();
    aiPhase = 'input';
    aiText = '';
    aiFailure = null;
    aiDoneLine = '';
    aiCard = null;
    aiAccounts = null;
    stReset();
  }

  // Кошельки и категории для карточки — тот же /api/reports/accounts, что у
  // бота, через fetchReport (кэш). Системные категории (Transfer, Transfer
  // commission — system_kind 1/2) и архивные счета в списки не попадают.
  function aiLoadAccounts(force) {
    if (force) {
      Object.keys(reportsCache).forEach(function (k) {
        if (k.indexOf('accounts?') === 0) delete reportsCache[k];
      });
    }
    return fetchReport('accounts', {}).then(function (data) {
      if (!data) return null;
      var live = data.accounts.filter(function (a) { return !a.is_archived; });
      aiAccounts = {
        wallets: live.filter(function (a) { return a.kind === 'wallet'; }),
        categories: live.filter(function (a) { return a.kind === 'category' && a.system_kind === 0; }),
      };
      return aiAccounts;
    });
  }

  function aiFindWallet(uuid) {
    if (!aiAccounts || !uuid) return null;
    for (var i = 0; i < aiAccounts.wallets.length; i++) if (aiAccounts.wallets[i].uuid === uuid) return aiAccounts.wallets[i];
    return null;
  }

  function aiFindCategory(uuid) {
    if (!aiAccounts || !uuid) return null;
    for (var i = 0; i < aiAccounts.categories.length; i++) {
      if (aiAccounts.categories[i].uuid === uuid) return aiAccounts.categories[i];
    }
    return null;
  }

  // Карточка: batch_id и uuid операции — один раз при показе, повтор записи
  // после сбоя идёт с теми же значениями, и wallet-api вернёт тот же seq.
  function aiNewCard(sourceText) {
    var now = new Date();
    return {
      batchId: uuidV4(),
      opUuid: uuidV4(),
      sourceText: sourceText,
      amount: '',
      walletUuid: '',
      categoryUuid: '',
      date: isoDate(now),
      time: localTime(now),
      comment: sourceText,
      walletHint: '', // подпись/причина у поля кошелька
      walletAsk: false,
      categoryAsk: false,
      walletFirst: [], // uuid, которые resolver предложил первыми
      walletForce: null, // { uuid, name } — "всё равно в «…»" при currency_mismatch
      categoryFirst: [],
      notes: [],
      busy: false,
      error: '',
    };
  }

  var AI_NOTE_TEXT = {
    currency_dropped: 'Валюта из текста не учтена — сумма записывается в валюте кошелька',
    comment_truncated: 'Комментарий обрезан',
  };

  function aiCardFromDraft(result, sourceText) {
    var card = aiNewCard(sourceText);
    var e = result.expense || {};
    var r = result.resolution || {};
    card.amount = e.amount || '';
    if (e.datetime && /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(e.datetime)) {
      card.date = e.datetime.slice(0, 10);
      card.time = e.datetime.slice(11);
    }
    card.comment = e.comment || '';
    card.notes = (result.notes || []).map(function (n) { return AI_NOTE_TEXT[n] || n; });

    var cat = r.category || {};
    if (cat.kind === 'found' && cat.found) card.categoryUuid = cat.found.uuid;
    if (cat.kind === 'ask') card.categoryAsk = true;
    card.categoryFirst = (cat.candidates || []).map(function (c) { return c.uuid; });

    var w = r.wallet || {};
    card.walletFirst = (w.candidates || []).map(function (c) { return c.uuid; });
    if (w.kind === 'found' && w.found) {
      card.walletUuid = w.found.uuid;
      if (w.by_currency && e.currency_hint) card.walletHint = 'Выбран по валюте из текста (' + e.currency_hint + ')';
    } else if (w.kind === 'ask') {
      card.walletAsk = true;
      if (w.why === 'currency_mismatch' && w.force) {
        card.walletHint = 'В тексте ' + (e.currency_hint || '') + ', а «' + w.force.name + '» в ' + w.force.iso_code;
        card.walletForce = { uuid: w.force.uuid, name: w.force.name };
      }
    } else if (w.kind === 'reject') {
      if (w.why === 'no_wallet_in_currency') card.walletHint = 'Нет кошелька в ' + (e.currency_hint || 'этой валюте');
      else if (w.why === 'no_wallets') card.walletHint = 'В кошельке нет ни одного счёта — создайте его в приложении';
    }
    return card;
  }

  // Проверки перед записью: сумма — положительное число не больше чем с
  // precision знаками выбранного кошелька, дата и время — не в будущем.
  function aiCardProblems(card) {
    var p = { amount: false, date: false, missing: false };
    var amount = card.amount.trim().replace(',', '.');
    var wallet = aiFindWallet(card.walletUuid);
    var m = /^(\d+)(?:\.(\d+))?$/.exec(amount);
    if (!m || parseFloat(amount) <= 0) p.amount = true;
    else if (wallet && m[2] && m[2].length > parseInt(wallet.precision || '2', 10)) p.amount = true;
    if (!/^\d{4}-\d{2}-\d{2}$/.test(card.date) || !/^\d{2}:\d{2}(:\d{2})?$/.test(card.time)) {
      p.date = true;
    } else {
      var t = card.time.length === 5 ? card.time + ':00' : card.time;
      if (new Date(card.date + 'T' + t) > new Date()) p.date = true;
    }
    if (!wallet || !aiFindCategory(card.categoryUuid)) p.missing = true;
    return p;
  }

  // Список: сначала предложенные resolver (в их порядке), затем
  // "всё равно в «…»" (currency_mismatch), затем остальные по имени.
  function aiOptionsHtml(items, selected, firstUuids, force, placeholder) {
    var first = [];
    firstUuids.forEach(function (u) {
      items.forEach(function (a) { if (a.uuid === u && first.indexOf(a) < 0) first.push(a); });
    });
    var forced = null;
    if (force) {
      items.forEach(function (a) { if (a.uuid === force.uuid) forced = a; });
    }
    var rest = items.filter(function (a) { return first.indexOf(a) < 0 && a !== forced; });
    function opt(a, label) {
      return '<option value="' + escapeHtml(a.uuid) + '"' + (a.uuid === selected ? ' selected' : '') + '>' +
        escapeHtml(label) + '</option>';
    }
    function walletLabel(a) { return a.iso_code ? a.name + ' · ' + a.iso_code : a.name; }
    return '<option value=""' + (selected ? '' : ' selected') + '>' + escapeHtml(placeholder) + '</option>' +
      first.map(function (a) { return opt(a, walletLabel(a)); }).join('') +
      (forced ? opt(forced, forced.name + ' — всё равно в «' + forced.name + '»') : '') +
      rest.map(function (a) { return opt(a, walletLabel(a)); }).join('');
  }

  function aiCardHtml(card) {
    if (!aiAccounts) return '<section class="report-section ai-card"><p class="sub">Загрузка кошельков…</p></section>';
    var wallet = aiFindWallet(card.walletUuid);
    var walletLabel = card.walletAsk && !card.walletUuid ? 'С какого кошелька?' : 'Кошелёк';
    var categoryLabel = card.categoryAsk && !card.categoryUuid ? 'Какая категория?' : 'Категория';
    return (
      '<section class="report-section ai-card" id="ai-card">' +
      '<p class="ai-card-lead">' + (card.fromDraft ? 'Понял из текста — проверьте перед записью:' : 'Заполните трату:') + '</p>' +
      '<div class="ai-card-grid">' +
      '<label class="ai-field">Сумма<span class="ai-amount-row">' +
      '<input type="text" inputmode="decimal" id="ai-amount" autocomplete="off" value="' + escapeHtml(card.amount) + '">' +
      '<span class="ai-currency" id="ai-currency">' + escapeHtml(wallet ? wallet.iso_code : '—') + '</span>' +
      '</span></label>' +
      '<label class="ai-field"><span id="ai-wallet-label">' + walletLabel + '</span>' +
      '<select id="ai-wallet">' +
      aiOptionsHtml(aiAccounts.wallets, card.walletUuid, card.walletFirst, card.walletForce, 'Выберите кошелёк') +
      '</select>' +
      (card.walletHint ? '<span class="ai-field-hint">' + escapeHtml(card.walletHint) + '</span>' : '') +
      '</label>' +
      '<label class="ai-field"><span id="ai-category-label">' + categoryLabel + '</span>' +
      '<select id="ai-category">' +
      aiOptionsHtml(aiAccounts.categories, card.categoryUuid, card.categoryFirst, null, 'Выберите категорию') +
      '</select></label>' +
      '<label class="ai-field">Дата и время<span class="ai-datetime-row">' +
      '<input type="date" id="ai-date" value="' + escapeHtml(card.date) + '">' +
      '<input type="time" id="ai-time" step="1" value="' + escapeHtml(card.time) + '">' +
      '</span></label>' +
      '<label class="ai-field ai-field-wide">Комментарий' +
      '<input type="text" id="ai-comment" value="' + escapeHtml(card.comment) + '"></label>' +
      '</div>' +
      (card.notes.length ? '<ul class="ai-notes">' + card.notes.map(function (n) {
        return '<li>' + escapeHtml(n) + '</li>';
      }).join('') + '</ul>' : '') +
      (card.sourceText ? '<p class="ai-source">Исходный текст: «' + escapeHtml(card.sourceText) + '»</p>' : '') +
      '<p class="err ai-card-error" id="ai-card-error"' + (card.error ? '' : ' hidden') + '>' + escapeHtml(card.error) + '</p>' +
      '<div class="ai-card-actions">' +
      '<button type="button" class="btn" id="ai-save-btn">' + (card.busy ? 'Записываю…' : 'Записать') + '</button>' +
      '<button type="button" class="btn btn-secondary" id="ai-card-cancel-btn">Отмена</button>' +
      '</div>' +
      '</section>'
    );
  }

  function renderAiRoot() {
    var root = document.getElementById('ai-root');
    if (!root) return;
    // Раздел — только если wallet-ai объявил parse_expense (без базы ai
    // бывает и наоборот: только импорт, см. aiHas).
    if (!aiHas('parse_expense')) {
      root.innerHTML = '';
      return;
    }
    var parsing = aiPhase === 'parsing';
    var status = '';
    if (parsing) {
      status = '<div class="ai-status"><span class="ai-spinner" aria-hidden="true"></span>Разбираю…' +
        '<button type="button" class="btn btn-secondary" id="ai-cancel-btn">Отменить</button></div>';
    } else if (aiPhase === 'input' && aiFailure) {
      status = '<div class="ai-status ai-status-fail"><span>' + escapeHtml(aiFailure.message) + '</span>' +
        '<button type="button" class="btn btn-secondary" id="ai-manual-btn">Заполнить вручную</button></div>';
    } else if (aiPhase === 'input' && aiDoneLine) {
      status = '<div class="ai-status ai-status-done">' + aiDoneLine + '</div>';
    }
    root.innerHTML =
      '<section class="report-section ai-input">' +
      '<h2>Трата своими словами</h2>' +
      '<textarea id="ai-text" rows="3" placeholder="Например: вчера такси 450 с тинькоффа"' +
      (parsing || aiPhase === 'card' ? ' disabled' : '') + '>' + escapeHtml(aiText) + '</textarea>' +
      '<div class="ai-input-row">' +
      '<span class="ai-counter" id="ai-counter"></span>' +
      (aiPhase === 'card' ? '' : '<button type="button" class="btn" id="ai-parse-btn">Разобрать</button>') +
      '</div>' +
      status +
      '</section>' +
      (aiPhase === 'card' && aiCard ? aiCardHtml(aiCard) : '');
    wireAiRoot();
    aiUpdateInputState();
    if (aiPhase === 'card' && aiCard) aiUpdateCardState();
  }

  function aiUpdateInputState() {
    var len = aiText.length;
    var counter = document.getElementById('ai-counter');
    if (counter) {
      counter.textContent = len + ' / ' + AI_TEXT_MAX;
      counter.classList.toggle('over', len > AI_TEXT_MAX);
    }
    var btn = document.getElementById('ai-parse-btn');
    if (btn) btn.disabled = aiPhase !== 'input' || !aiText.trim() || len > AI_TEXT_MAX;
  }

  // Подсветка полей и доступность "Записать" — на каждое изменение, без
  // перерисовки карточки (иначе ввод терял бы фокус на каждом символе).
  function aiUpdateCardState() {
    if (!aiCard || !aiAccounts) return;
    var p = aiCardProblems(aiCard);
    var amountEl = document.getElementById('ai-amount');
    if (!amountEl) return;
    amountEl.classList.toggle('invalid', p.amount && aiCard.amount !== '');
    document.getElementById('ai-date').classList.toggle('invalid', p.date);
    document.getElementById('ai-time').classList.toggle('invalid', p.date);
    var wallet = aiFindWallet(aiCard.walletUuid);
    document.getElementById('ai-currency').textContent = wallet ? wallet.iso_code : '—';
    document.getElementById('ai-wallet-label').textContent =
      aiCard.walletAsk && !aiCard.walletUuid ? 'С какого кошелька?' : 'Кошелёк';
    document.getElementById('ai-category-label').textContent =
      aiCard.categoryAsk && !aiCard.categoryUuid ? 'Какая категория?' : 'Категория';
    document.getElementById('ai-save-btn').disabled = aiCard.busy || p.amount || p.date || p.missing;
    var errEl = document.getElementById('ai-card-error');
    errEl.textContent = aiCard.error;
    errEl.hidden = !aiCard.error;
  }

  function wireAiRoot() {
    var textEl = document.getElementById('ai-text');
    textEl.addEventListener('input', function () {
      aiText = textEl.value;
      aiUpdateInputState();
    });
    // Enter — разобрать, Shift+Enter — перенос строки.
    textEl.addEventListener('keydown', function (ev) {
      if (ev.key === 'Enter' && !ev.shiftKey && !ev.isComposing) {
        ev.preventDefault();
        aiStartParse();
      }
    });
    var parseBtn = document.getElementById('ai-parse-btn');
    if (parseBtn) parseBtn.addEventListener('click', aiStartParse);
    var cancelBtn = document.getElementById('ai-cancel-btn');
    if (cancelBtn) {
      cancelBtn.addEventListener('click', function () {
        aiCancelParsing();
        renderAiRoot();
      });
    }
    var manualBtn = document.getElementById('ai-manual-btn');
    if (manualBtn) manualBtn.addEventListener('click', aiOpenManual);
    if (aiPhase === 'card' && aiCard && aiAccounts) wireAiCard();
  }

  function wireAiCard() {
    function bind(id, field, event) {
      var el = document.getElementById(id);
      el.addEventListener(event, function () {
        aiCard[field] = el.value;
        aiCard.error = '';
        aiUpdateCardState();
      });
    }
    bind('ai-amount', 'amount', 'input');
    bind('ai-wallet', 'walletUuid', 'change');
    bind('ai-category', 'categoryUuid', 'change');
    bind('ai-date', 'date', 'input');
    bind('ai-time', 'time', 'input');
    bind('ai-comment', 'comment', 'input');
    document.getElementById('ai-save-btn').addEventListener('click', function () { aiPush(false); });
    document.getElementById('ai-card-cancel-btn').addEventListener('click', function () {
      aiCard = null;
      aiPhase = 'input';
      renderAiRoot();
    });
  }

  function aiFail(message) {
    aiPhase = 'input';
    aiFailure = { message: message };
    aiJobId = null;
    renderAiRoot();
  }

  var AI_REJECT_TEXT = {
    amount_not_in_text: 'суммы нет в тексте',
    future_date: 'дата в будущем',
    too_old: 'дата старше года',
  };

  function aiStartParse() {
    var text = aiText.trim();
    if (aiPhase !== 'input' || !text || aiText.length > AI_TEXT_MAX) return;
    aiAttempt++;
    var attempt = aiAttempt;
    aiPhase = 'parsing';
    aiFailure = null;
    aiDoneLine = '';
    aiCard = null;
    aiJobId = null;
    renderAiRoot();

    var now = new Date();
    var input = { text: text, now: { date: isoDate(now), time: localTime(now) } };
    var lastWallet = getAiLastWallet();
    if (lastWallet) input.default_wallet_uuid = lastWallet;
    // Загружаем списки параллельно с разбором — к карточке они уже будут.
    aiLoadAccounts(false).catch(function () { /* покажем ошибку уже на карточке */ });

    apiFetch('/api/ai/jobs', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ kind: 'parse_expense', idempotency_key: 'web:' + uuidV4(), input: input }),
    })
      .then(function (res) {
        if (res.status === 401) {
          renderLogin();
          return null;
        }
        return res.json().catch(function () { return {}; }).then(function (data) {
          if (res.status === 202) return data;
          var err = new Error(data && data.error ? data.error : 'HTTP ' + res.status);
          err.status = res.status;
          throw err;
        });
      })
      .then(function (data) {
        if (!data) return;
        if (!aiAttemptAlive(attempt)) {
          // Отменили, пока задание создавалось, — снимаем и его.
          if (data.job_id) aiDeleteJob(data.job_id);
          return;
        }
        aiJobId = data.job_id;
        aiPoll(attempt, data.job_id);
      })
      .catch(function (err) {
        if (!aiAttemptAlive(attempt)) return;
        if (err.status === 429) aiFail('ИИ занят, попробуйте через минуту');
        else if (err.status === 503) aiFail('ИИ сейчас выключен');
        else aiFail('Не удалось отправить текст ИИ: ' + err.message);
      });
  }

  // Long-poll: ?wait=25 (до 30 с таймаута гейтвея), пока задание queued/running.
  function aiPoll(attempt, jobId) {
    apiFetch('/api/ai/jobs/' + encodeURIComponent(jobId) + '?wait=25', { credentials: 'include' })
      .then(function (res) {
        if (!aiAttemptAlive(attempt)) {
          if (!document.getElementById('ai-root')) aiDeleteJob(jobId); // "Отчёты" закрыли посреди разбора
          return null;
        }
        if (res.status === 401) {
          renderLogin();
          return null;
        }
        if (res.status === 404) {
          aiFail('Результат потерялся, попробуйте ещё раз');
          return null;
        }
        if (!res.ok) throw new Error('HTTP ' + res.status);
        return res.json();
      })
      .then(function (job) {
        if (!job || !aiAttemptAlive(attempt)) return;
        if (job.status === 'queued' || job.status === 'running') {
          aiPoll(attempt, jobId);
          return;
        }
        aiJobId = null;
        if (job.status === 'failed') {
          aiFail('ИИ не ответил вовремя');
          return;
        }
        if (job.status !== 'done' || !job.result) {
          aiFail('Разбор прерван, попробуйте ещё раз');
          return;
        }
        aiHandleResult(job.result);
      })
      .catch(function (err) {
        if (!aiAttemptAlive(attempt)) return;
        aiFail('Не удалось получить ответ ИИ: ' + err.message);
      });
  }

  function aiHandleResult(result) {
    if (result.outcome === 'draft') {
      aiCard = aiCardFromDraft(result, aiText.trim());
      aiCard.fromDraft = true;
      aiPhase = 'card';
      aiShowCard();
      return;
    }
    if (result.outcome === 'not_expense') {
      aiFail('Не нашёл тут трату');
      return;
    }
    var reasons = [];
    (result.reasons || []).forEach(function (r) {
      var t = AI_REJECT_TEXT[r] || 'сумма или дата';
      if (reasons.indexOf(t) < 0) reasons.push(t);
    });
    aiFail('Не получилось разобрать: ' + (reasons.length ? reasons.join(', ') : 'сумма или дата'));
  }

  // Карточка рисуется сразу, а списки догружаются (обычно они уже в кэше).
  function aiShowCard() {
    renderAiRoot();
    aiLoadAccounts(false)
      .then(function (accounts) {
        if (!accounts || aiPhase !== 'card') return;
        // Предвыбор resolver, которого нет в живых списках (архивный счёт),
        // не оставляем выбранным "в никуда".
        if (aiCard.walletUuid && !aiFindWallet(aiCard.walletUuid)) aiCard.walletUuid = '';
        if (aiCard.categoryUuid && !aiFindCategory(aiCard.categoryUuid)) aiCard.categoryUuid = '';
        renderAiRoot();
      })
      .catch(function (err) {
        var root = document.getElementById('ai-card');
        if (root) root.innerHTML = reportsErrorHtml('Не удалось загрузить кошельки: ' + err.message);
      });
  }

  function aiOpenManual() {
    aiCard = aiNewCard(aiText.trim());
    aiCard.fromDraft = false;
    aiFailure = null;
    aiPhase = 'card';
    aiShowCard();
  }

  function aiDeleteJob(jobId) {
    apiFetch('/api/ai/jobs/' + encodeURIComponent(jobId), { method: 'DELETE', credentials: 'include' })
      .catch(function () { /* не снялось — задание само истечёт через TTL */ });
  }

  // "Отменить", уход с вкладки "ИИ" и новый заход на "Отчёты": текущая
  // попытка устаревает, задание снимается, текст остаётся в поле.
  function aiCancelParsing() {
    if (aiPhase !== 'parsing') return;
    aiAttempt++;
    aiPhase = 'input';
    if (aiJobId) aiDeleteJob(aiJobId);
    aiJobId = null;
  }

  var AI_PUSH_ERROR_TEXT = {
    reader_cannot_write: 'Вы читатель в этом кошельке — записывать траты нельзя',
    missing_reference: 'Кошелёк или категория удалены — выберите другие',
  };

  // POST /sync/push — одна операция расхода: acc_fr — кошелёк, acc_to —
  // категория. retriedDevice — уже был один повтор после device_required
  // (сессия, выпущенная до выдачи браузеру device_id: /auth/refresh даёт
  // токен с ним).
  function aiPush(retriedDevice) {
    var card = aiCard;
    if (!card || card.busy) return;
    var p = aiCardProblems(card);
    if (p.amount || p.date || p.missing) return;
    var wallet = aiFindWallet(card.walletUuid);
    var category = aiFindCategory(card.categoryUuid);
    var amount = card.amount.trim().replace(',', '.');
    var time = card.time.length === 5 ? card.time + ':00' : card.time;
    card.busy = true;
    card.error = '';
    var saveBtn = document.getElementById('ai-save-btn');
    if (saveBtn) saveBtn.textContent = 'Записываю…';
    aiUpdateCardState();

    function finish(error) {
      card.busy = false;
      card.error = error;
      if (aiCard !== card) return;
      var btn = document.getElementById('ai-save-btn');
      if (btn) btn.textContent = 'Записать';
      aiUpdateCardState();
    }

    apiFetch('/sync/push', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        batch_id: card.batchId,
        device_name: 'Веб-браузер',
        changes: {
          operation: [{
            uuid: card.opUuid,
            date: card.date + ' ' + time,
            acc_fr_uuid: wallet.uuid,
            acc_to_uuid: category.uuid,
            amount: amount,
            comment: card.comment,
          }],
        },
      }),
    })
      .then(function (res) {
        if (res.status === 401) {
          renderLogin();
          return;
        }
        return res.json().catch(function () { return {}; }).then(function (data) {
          var code = data && data.error ? data.error : '';
          if (res.ok) {
            setAiLastWallet(wallet.uuid);
            aiDoneLine = 'Записано: ' + fmtNative(amount, wallet.symbol || wallet.iso_code) + ' · ' +
              escapeHtml(category.name) + ' · ' + escapeHtml(wallet.name);
            aiCard = null;
            aiText = '';
            aiPhase = 'input';
            renderAiRoot();
            // Новая трата должна появиться в отчётах без F5 — как при смене периода.
            reportsCache = {};
            refreshPeriod();
            return;
          }
          if (res.status === 403 && code === 'device_required') {
            if (retriedDevice) {
              finish('Перезайдите, чтобы записывать траты из браузера');
              return;
            }
            return fetch('/auth/refresh', { method: 'POST', credentials: 'include' }).then(function () {
              card.busy = false;
              aiPush(true);
            });
          }
          if (res.status === 409 && code === 'missing_reference') {
            finish(AI_PUSH_ERROR_TEXT.missing_reference);
            aiLoadAccounts(true).then(function () {
              if (aiCard !== card) return;
              if (!aiFindWallet(card.walletUuid)) card.walletUuid = '';
              if (!aiFindCategory(card.categoryUuid)) card.categoryUuid = '';
              renderAiRoot();
            });
            return;
          }
          if (res.status >= 500) {
            finish('Не удалось записать, попробуйте ещё раз');
            return;
          }
          finish(AI_PUSH_ERROR_TEXT[code] || code || 'HTTP ' + res.status);
        });
      })
      .catch(function () {
        finish('Не удалось записать, попробуйте ещё раз');
      });
  }

  // --- «ИИ» → «Импорт выписки» (add-ai-statement-import) -------------------
  // Выписка (текст или файл) → импорт в wallet-ai, разбор идёт в фоне и не
  // требует открытой вкладки. Готовый импорт проверяется на экране
  // #/reports/ai/import/<id>: группы строк, правки (автосохранение PATCH rows),
  // запись готовых операций в POST /sync/push пачками по 50 с отметкой
  // /committed после каждой. ИИ сам ничего не пишет.
  //
  // Список опрашивается (D2): раз в 5 с, пока раздел открыт и есть
  // незавершённые импорты, иначе раз в 30 с — ради метки на пункте «ИИ».
  // Таймер останавливается, когда незавершённых нет.
  var ST_FILE_MAX = 5 * 1024 * 1024;
  var ST_FILE_EXT = ['pdf', 'csv', 'txt'];
  var ST_SEEN_KEY = 'aiSeenImports';
  var ST_PROFILE_KEY = 'aiImportProfile';
  var ST_WALLET_KEY = 'aiImportWalletUuid';
  var ST_PAGE = 200;
  var ST_PUSH_BATCH = 50;
  var ST_ACTIVE = ['queued', 'extracting', 'classifying'];
  var ST_GROUPS = [
    ['ready', 'Готово к записи'],
    ['needs_category', 'Нужна категория'],
    ['possible_duplicate', 'Похоже на дубль'],
    ['check', 'Проверьте'],
    ['exists', 'Уже есть'],
    ['imported', 'Уже импортировано'],
    ['income_transfer', 'Доходы и переводы'],
    ['unparsed', 'Не разобрано'],
  ];
  var ST_FAILURE_TEXT = {
    no_text: 'в PDF нет текста — похоже, это скан',
    no_operations: 'не нашёл в документе ни одной операции',
    timeout: 'ИИ не успел разобрать часть выписки',
    unavailable: 'ИИ был недоступен слишком долго',
  };
  var ST_CHECK_TEXT = {
    amount_not_in_text: 'сумма не найдена в тексте',
    date_not_in_text: 'дата не найдена в тексте',
    currency_mismatch: 'другая валюта',
  };
  var ST_SOURCE_TEXT = { rule: 'правило', llm: 'ИИ', user: 'вы', manual: 'вы' };
  var ST_PATCH_ERROR = {
    bad_amount: 'Сумма — положительное число, например 1290.50',
    bad_date: 'Дата — не в будущем',
    unknown_category: 'Такой категории больше нет — обновите страницу',
    row_committed: 'Строка уже записана',
    not_ready: 'Импорт ещё не готов',
    bad_line: 'Этой строки в выписке нет',
  };

  var stImports = null; // [] из GET /api/ai/imports; null — ещё не загружен
  var stListError = '';
  var stListNotice = ''; // ответ на «Повторить» в списке
  var stProfiles = null; // [] из GET /api/ai/statement-profiles
  var stPollTimer = null;
  var stForm = null; // см. stNewForm
  var stConfirmDelete = null; // import_id, у которого открыто «Удалить?»
  var stHighlight = null; // import_id, подсвеченный после 429 import_in_progress
  var stRename = null; // {id, name} — открытое переименование своего формата
  var stConfirmProfileDelete = null; // id своего формата под «Удалить?»
  var stDetail = null; // экран проверки, см. stShowImport

  function stGetPref(key) {
    try {
      return localStorage.getItem(key) || '';
    } catch (e) {
      return '';
    }
  }

  function stSetPref(key, value) {
    try {
      localStorage.setItem(key, value);
    } catch (e) {
      // не запомнили — в следующий раз будет значение по умолчанию
    }
  }

  // Какие готовые импорты уже открывали в этом браузере (D3) — сервер о
  // «просмотрено» не знает.
  function stSeen() {
    try {
      var v = JSON.parse(localStorage.getItem(ST_SEEN_KEY) || '[]');
      return Array.isArray(v) ? v : [];
    } catch (e) {
      return [];
    }
  }

  function stSaveSeen(list) {
    try {
      localStorage.setItem(ST_SEEN_KEY, JSON.stringify(list));
    } catch (e) {
      // метка вернётся после перезагрузки — не страшно
    }
  }

  function stMarkSeen(id) {
    var seen = stSeen();
    if (seen.indexOf(id) >= 0) return;
    seen.push(id);
    stSaveSeen(seen);
    stUpdateBadge();
  }

  function aiHas(feature) {
    return aiStatus === true && aiFeatures.indexOf(feature) >= 0;
  }

  function stNewForm() {
    return {
      mode: 'text',
      text: '',
      file: null,
      walletUuid: stGetPref(ST_WALLET_KEY),
      profile: stGetPref(ST_PROFILE_KEY) || 'auto',
      error: '',
      busy: false,
    };
  }

  function stReset() {
    clearTimeout(stPollTimer);
    stPollTimer = null;
    if (stDetail) clearTimeout(stDetail.timer);
    stImports = null;
    stListError = '';
    stListNotice = '';
    stProfiles = null;
    stForm = stNewForm();
    stConfirmDelete = null;
    stHighlight = null;
    stRename = null;
    stConfirmProfileDelete = null;
    stDetail = null;
  }

  // JSON-вызов wallet-ai: 401 — экран входа (null), ошибка — Error со
  // status и телом ответа (body.import_id у 429 import_in_progress).
  function stApi(method, url, body) {
    var options = { method: method, credentials: 'include' };
    if (body !== undefined) {
      options.headers = { 'Content-Type': 'application/json' };
      options.body = JSON.stringify(body);
    }
    return apiFetch(url, options).then(function (res) {
      if (res.status === 401) {
        renderLogin();
        return null;
      }
      if (res.status === 204) return {};
      return res.json().catch(function () { return {}; }).then(function (data) {
        if (!res.ok) {
          var err = new Error(data && data.error ? data.error : 'HTTP ' + res.status);
          err.status = res.status;
          err.body = data || {};
          throw err;
        }
        return data;
      });
    });
  }

  function stImportUrl(id) {
    return '/api/ai/imports/' + encodeURIComponent(id);
  }

  // Статус ИИ пришёл: раздел, список, профили и кошельки формы.
  function stOnStatus() {
    stRender();
    if (!aiHas('statement_import')) return;
    stLoadImports();
    stLoadProfiles();
    aiLoadAccounts(false).then(function () {
      stRenderWalletOptions();
      if (stDetail) stRenderDetail();
      else stRenderList();
    }, function () { /* без списка кошельков форма просто остаётся неактивной */ });
  }

  // Каркас раздела: форма, список и «Мои форматы» — в своих контейнерах,
  // чтобы опрос списка не перерисовывал поле, в котором пользователь пишет.
  function stRender() {
    var root = document.getElementById('st-root');
    if (!root) return;
    var aiRoot = document.getElementById('ai-root');
    if (aiRoot) aiRoot.hidden = !!stDetail;
    if (!aiHas('statement_import')) {
      root.innerHTML = '';
      return;
    }
    if (stDetail) {
      root.innerHTML = '<div id="st-detail"></div>';
      stRenderDetail();
      if (!stDetail.data && !stDetail.loading) stLoadDetail(false);
      return;
    }
    root.innerHTML =
      '<section class="report-section st-section">' +
      '<h2>Импорт выписки</h2>' +
      '<p class="sub st-lead">Выписка банка (PDF с текстом, CSV или скопированный текст) — ИИ разберёт её в фоне, ' +
      'страницу можно закрыть. Потом проверьте операции и запишите их одним действием.</p>' +
      '<div id="st-form"></div>' +
      '<div id="st-list"></div>' +
      '<div id="st-own"></div>' +
      '</section>';
    stRenderForm();
    stRenderList();
    stRenderOwn();
    stWireSection(root);
  }

  // --- Форма загрузки ---

  function stWalletOptionsHtml(selected) {
    if (!aiAccounts) return '<option value="">Загрузка кошельков…</option>';
    return '<option value="">Выберите кошелёк</option>' + aiAccounts.wallets.map(function (w) {
      return '<option value="' + escapeHtml(w.uuid) + '"' + (w.uuid === selected ? ' selected' : '') + '>' +
        escapeHtml(w.iso_code ? w.name + ' · ' + w.iso_code : w.name) + '</option>';
    }).join('');
  }

  function stProfileOptionsHtml(selected) {
    var list = stProfiles || [];
    function opt(id, label) {
      return '<option value="' + escapeHtml(id) + '"' + (id === selected ? ' selected' : '') + '>' + escapeHtml(label) + '</option>';
    }
    var own = list.filter(function (p) { return p.kind === 'own'; });
    return opt('auto', 'Определить автоматически') +
      list.filter(function (p) { return p.kind === 'builtin'; }).map(function (p) { return opt(p.id, p.name); }).join('') +
      (own.length ? '<optgroup label="Мои форматы">' + own.map(function (p) { return opt(p.id, p.name); }).join('') + '</optgroup>' : '') +
      opt('none', 'Без подсказок');
  }

  // Выбор из прошлого раза, которого больше нет (кошелёк в архиве, свой
  // формат удалён), не остаётся выбранным «в никуда».
  function stNormalizeForm() {
    var f = stForm;
    if (aiAccounts && f.walletUuid && !aiFindWallet(f.walletUuid)) f.walletUuid = '';
    if (stProfiles && f.profile !== 'auto' && f.profile !== 'none' &&
        !stProfiles.some(function (p) { return p.id === f.profile; })) {
      f.profile = 'auto';
    }
  }

  function stCanSubmit() {
    var f = stForm;
    return !f.busy && !!aiFindWallet(f.walletUuid) && (f.mode === 'text' ? !!f.text.trim() : !!f.file);
  }

  function stFileSizeText(bytes) {
    if (bytes < 1024 * 1024) return Math.max(1, Math.round(bytes / 1024)) + ' КБ';
    return (bytes / 1024 / 1024).toFixed(1).replace('.', ',') + ' МБ';
  }

  function stRenderForm() {
    var el = document.getElementById('st-form');
    if (!el) return;
    stNormalizeForm();
    var f = stForm;
    var source = f.mode === 'text'
      ? '<textarea id="st-text" rows="6" placeholder="Скопируйте сюда операции из выписки или приложения банка"' +
        (f.busy ? ' disabled' : '') + '>' + escapeHtml(f.text) + '</textarea>'
      : '<div class="st-file-row">' +
        '<label class="btn-chip st-file-btn">Выбрать файл<input type="file" id="st-file" accept=".pdf,.csv,.txt" hidden' +
        (f.busy ? ' disabled' : '') + '></label>' +
        '<span class="st-file-name">' + (f.file ? escapeHtml(f.file.name) + ' · ' + stFileSizeText(f.file.size)
          : 'PDF с текстом, CSV или TXT до 5 МБ') + '</span></div>';
    el.innerHTML =
      '<div class="st-form">' +
      '<div class="st-form-grid">' +
      '<label class="ai-field">Кошелёк<select id="st-wallet"' + (f.busy ? ' disabled' : '') + '>' +
      stWalletOptionsHtml(f.walletUuid) + '</select></label>' +
      '<label class="ai-field">Банк или формат<select id="st-profile"' + (f.busy ? ' disabled' : '') + '>' +
      stProfileOptionsHtml(f.profile) + '</select></label>' +
      '</div>' +
      '<div class="ops-seg-group st-mode">' +
      '<button type="button" class="ops-seg-btn' + (f.mode === 'text' ? ' active' : '') + '" data-st-mode="text">Вставить текст</button>' +
      '<button type="button" class="ops-seg-btn' + (f.mode === 'file' ? ' active' : '') + '" data-st-mode="file">Загрузить файл</button>' +
      '</div>' +
      source +
      '<p class="err st-form-error"' + (f.error ? '' : ' hidden') + ' id="st-form-error">' + escapeHtml(f.error) + '</p>' +
      '<button type="button" class="btn st-submit" id="st-submit">' + (f.busy ? 'Отправляю…' : 'Разобрать выписку') + '</button>' +
      '</div>';
    stUpdateFormState();
  }

  function stUpdateFormState() {
    var btn = document.getElementById('st-submit');
    if (btn) btn.disabled = !stCanSubmit();
  }

  function stRenderWalletOptions() {
    var sel = document.getElementById('st-wallet');
    if (!sel || !stForm) return;
    stNormalizeForm();
    sel.innerHTML = stWalletOptionsHtml(stForm.walletUuid);
    stUpdateFormState();
  }

  function stRenderProfileOptions() {
    var sel = document.getElementById('st-profile');
    if (!sel || !stForm) return;
    stNormalizeForm();
    sel.innerHTML = stProfileOptionsHtml(stForm.profile);
  }

  function stFileProblem(file) {
    var dot = file.name.lastIndexOf('.');
    var ext = dot < 0 ? '' : file.name.slice(dot + 1).toLowerCase();
    if (ST_FILE_EXT.indexOf(ext) < 0) return 'Подходят только PDF, CSV и TXT';
    if (file.size > ST_FILE_MAX) return 'Файл больше 5 МБ — выгрузите выписку за меньший период';
    if (file.size === 0) return 'Файл пустой';
    return '';
  }

  // FileReader → base64 без префикса data:…;base64, (D4).
  function stReadBase64(file) {
    return new Promise(function (resolve, reject) {
      var reader = new FileReader();
      reader.onload = function () {
        var s = String(reader.result);
        resolve(s.slice(s.indexOf(',') + 1));
      };
      reader.onerror = function () {
        var err = new Error('file');
        err.fileRead = true;
        reject(err);
      };
      reader.readAsDataURL(file);
    });
  }

  function stCreateErrorText(err) {
    var code = err.body && err.body.error;
    if (err.fileRead) return 'Не удалось прочитать файл — выберите его ещё раз';
    if (err.status === 429 && code === 'import_in_progress') return 'Уже разбирается другая выписка — дождитесь её или отмените';
    if (err.status === 429) return 'Сейчас разбирается много выписок — попробуйте через несколько минут';
    if (err.status === 413 || code === 'too_large') return 'Выписка слишком большая — выгрузите её за меньший период, например по месяцам';
    if (code === 'unsupported_file') return 'Такой файл не подходит — нужен PDF с текстом, CSV или TXT';
    if (code === 'empty') return 'Выписка пустая — вставьте текст или выберите другой файл';
    if (code === 'bad_base64') return 'Не удалось прочитать файл — выберите его ещё раз';
    if (code === 'unknown_wallet') return 'Кошелёк не найден — выберите другой';
    if (code === 'unknown_profile') return 'Такого формата больше нет — выбрано «Определить автоматически»';
    if (err.status === 503) return 'Импорт выписок сейчас недоступен — попробуйте позже';
    if (err.status === 502) return 'Не удалось проверить кошелёк — попробуйте ещё раз';
    if (!err.status) return 'Не удалось отправить выписку — проверьте соединение';
    return 'Не удалось отправить выписку: ' + (code || 'HTTP ' + err.status);
  }

  function stSubmit() {
    var f = stForm;
    if (!stCanSubmit()) return;
    f.busy = true;
    f.error = '';
    stHighlight = null;
    stRenderForm();
    stRenderList();
    var body = { wallet_uuid: f.walletUuid, profile: f.profile };
    var prepared;
    if (f.mode === 'text') {
      body.text = f.text;
      prepared = Promise.resolve();
    } else {
      prepared = stReadBase64(f.file).then(function (b64) {
        body.file = { name: f.file.name, content_base64: b64 };
      });
    }
    prepared
      .then(function () { return stApi('POST', '/api/ai/imports', body); })
      .then(function (data) {
        if (!data || stForm !== f) return;
        stSetPref(ST_WALLET_KEY, f.walletUuid);
        stSetPref(ST_PROFILE_KEY, f.profile);
        stForm = stNewForm();
        stForm.mode = f.mode;
        stRenderForm();
        stLoadImports();
      })
      .catch(function (err) {
        if (stForm !== f) return;
        f.busy = false;
        f.error = stCreateErrorText(err);
        var code = err.body && err.body.error;
        if (code === 'import_in_progress') stHighlight = err.body.import_id || null;
        if (code === 'unknown_profile') {
          f.profile = 'auto';
          stLoadProfiles();
        }
        stRenderForm();
        stRenderList();
      });
  }

  // --- Список импортов ---

  function stLoadImports() {
    if (!aiHas('statement_import')) return;
    clearTimeout(stPollTimer);
    stPollTimer = null;
    stApi('GET', '/api/ai/imports')
      .then(function (data) {
        if (!data || !document.getElementById('reports-shell')) return;
        stImports = data.imports || [];
        stListError = '';
        // Забытые id (импорт удалён или истёк) из списка «просмотренных» убираем.
        var ids = stImports.map(function (imp) { return imp.import_id; });
        var seen = stSeen();
        var kept = seen.filter(function (id) { return ids.indexOf(id) >= 0; });
        if (kept.length !== seen.length) stSaveSeen(kept);
      }, function (err) {
        stListError = err.status === 503 ? 'Импорт выписок сейчас недоступен' : 'Не удалось загрузить импорты: ' + err.message;
      })
      .then(function () {
        if (!document.getElementById('reports-shell')) return;
        stUpdateBadge();
        stRenderList();
        stSchedulePoll();
      });
  }

  function stSchedulePoll() {
    clearTimeout(stPollTimer);
    stPollTimer = null;
    if (!document.getElementById('reports-shell') || !aiHas('statement_import') || !stImports) return;
    var active = stImports.some(function (imp) { return ST_ACTIVE.indexOf(imp.status) >= 0; });
    if (!active) return;
    var inSection = reportsView === 'ai' && !stDetail;
    stPollTimer = setTimeout(stLoadImports, inSection ? 5000 : 30000);
  }

  // Метка на «ИИ» (и «Ещё» на телефоне): готовые импорты, ещё не открытые здесь.
  function stUpdateBadge() {
    var n = 0;
    if (aiHas('statement_import') && stImports) {
      var seen = stSeen();
      n = stImports.filter(function (imp) {
        return imp.status === 'ready' && seen.indexOf(imp.import_id) < 0;
      }).length;
    }
    [document.querySelector('.nav-item[data-view="ai"]'), document.getElementById('mobile-more-btn')].forEach(function (el) {
      if (!el) return;
      var badge = el.querySelector('.nav-badge');
      if (!n) {
        if (badge) el.removeChild(badge);
        return;
      }
      if (!badge) {
        badge = document.createElement('span');
        badge.className = 'nav-badge';
        el.appendChild(badge);
      }
      badge.textContent = String(n);
      badge.setAttribute('aria-label', 'Готовых выписок: ' + n);
    });
  }

  function stProfileText(imp) {
    if (imp.profile_detect === 'none') return 'Формат не определён — разобрано без подсказок';
    if (imp.profile_detect === 'ambiguous') return 'Похоже на несколько форматов — разобрано без подсказок';
    if (imp.profile && imp.profile.name) {
      return 'Формат: ' + imp.profile.name + (imp.profile.source === 'auto' ? ' (определён автоматически)' : '');
    }
    return '';
  }

  function stStatusText(imp) {
    var p = imp.progress || {};
    var c = imp.counts || {};
    var active = ST_ACTIVE.indexOf(imp.status) >= 0;
    var s;
    if (active && imp.paused_since) s = 'ИИ недоступен — разбор на паузе';
    else if (imp.status === 'queued') s = 'в очереди';
    else if (imp.status === 'extracting') s = p.total ? 'разбираю ' + p.done + ' из ' + p.total : 'разбираю';
    else if (imp.status === 'classifying') s = 'подбираю категории';
    else if (imp.status === 'ready') {
      var rows = c.rows || 0;
      s = 'готово: ' + rows + ' ' + pluralRu(rows, ['операция', 'операции', 'операций']);
      if (c.committed) s += ' · записано ' + c.committed;
    } else if (imp.status === 'done') s = 'записано ' + (c.committed || 0);
    else if (imp.status === 'failed') s = 'ошибка: ' + (ST_FAILURE_TEXT[imp.failure] || 'разбор не удался');
    else s = 'отменён';
    var expires = Date.parse(imp.expires_at);
    if (!active && !isNaN(expires) && expires - Date.now() < 14 * 86400000) {
      s += ' · удалится ' + formatDate(isoDate(new Date(expires)));
    }
    return s;
  }

  function stCreatedText(iso) {
    var t = Date.parse(iso);
    if (isNaN(t)) return '';
    var d = new Date(t);
    return formatDate(isoDate(d)) + ' ' + pad2(d.getHours()) + ':' + pad2(d.getMinutes());
  }

  function stImportRowHtml(imp) {
    var id = imp.import_id;
    var active = ST_ACTIVE.indexOf(imp.status) >= 0;
    var wallet = aiFindWallet(imp.wallet_uuid);
    var p = imp.progress;
    var bar = imp.status === 'extracting' && p && p.total > 0
      ? '<div class="st-progress"><span style="width:' + Math.round(100 * p.done / p.total) + '%"></span></div>' : '';
    var meta = [wallet ? wallet.name : '', stCreatedText(imp.created_at)].filter(Boolean).join(' · ');
    var profile = stProfileText(imp);
    var fresh = imp.status === 'ready' && stSeen().indexOf(id) < 0;
    var actions;
    if (stConfirmDelete === id) {
      actions = '<span class="st-confirm-text">' + (active ? 'Отменить разбор?' : 'Удалить импорт?') + '</span>' +
        '<button type="button" class="btn-chip access-danger" data-st-del-yes="' + escapeHtml(id) + '">' +
        (active ? 'Да, отменить' : 'Да, удалить') + '</button>' +
        '<button type="button" class="btn-chip" data-st-del-no>Нет</button>';
    } else {
      actions =
        (imp.status === 'ready' || imp.status === 'done'
          ? '<button type="button" class="btn-chip st-open-btn" data-st-open="' + escapeHtml(id) + '">' +
            (imp.status === 'ready' ? 'Проверить' : 'Открыть') + '</button>' : '') +
        (imp.status === 'failed' && (imp.failure === 'timeout' || imp.failure === 'unavailable')
          ? '<button type="button" class="btn-chip" data-st-retry="' + escapeHtml(id) + '">Повторить</button>' : '') +
        '<button type="button" class="btn-chip" data-st-del="' + escapeHtml(id) + '">' + (active ? 'Отменить' : 'Удалить') + '</button>';
    }
    return '<div class="st-import' + (stHighlight === id ? ' highlight' : '') + (fresh ? ' fresh' : '') + '">' +
      '<div class="st-import-main">' +
      '<div class="st-import-name">' + escapeHtml(imp.source_name || 'Текст') + '</div>' +
      '<div class="st-import-meta">' + escapeHtml(meta) + '</div>' +
      (profile ? '<div class="st-import-meta">' + escapeHtml(profile) + '</div>' : '') +
      '<div class="st-import-status st-status-' + escapeHtml(imp.status) + '">' + escapeHtml(stStatusText(imp)) + '</div>' +
      bar +
      '</div>' +
      '<div class="st-import-actions">' + actions + '</div>' +
      '</div>';
  }

  function stRenderList() {
    var el = document.getElementById('st-list');
    if (!el) return;
    var html = '<h3 class="st-list-title">Загруженные выписки</h3>';
    if (stListNotice) html += '<p class="err">' + escapeHtml(stListNotice) + '</p>';
    if (stListError) html += '<p class="err">' + escapeHtml(stListError) + '</p>';
    if (!stImports) html += stListError ? '' : '<p class="sub">Загрузка…</p>';
    else if (!stImports.length) html += '<p class="sub">Пока ни одной выписки.</p>';
    else html += '<div class="st-imports">' + stImports.map(stImportRowHtml).join('') + '</div>';
    el.innerHTML = html;
  }

  function stDeleteImport(id) {
    stConfirmDelete = null;
    stApi('DELETE', stImportUrl(id))
      .then(function () {}, function (err) {
        if (err.status !== 404) stListNotice = 'Не удалось удалить: ' + err.message;
      })
      .then(function () {
        if (stImports) stImports = stImports.filter(function (imp) { return imp.import_id !== id; });
        if (stHighlight === id) stHighlight = null;
        stUpdateBadge();
        stRenderList();
        stLoadImports();
      });
  }

  function stRetryImport(id) {
    stListNotice = '';
    stApi('POST', stImportUrl(id) + '/retry')
      .then(function () {}, function (err) {
        var code = err.body && err.body.error;
        stListNotice = code === 'import_in_progress' ? 'Уже разбирается другая выписка — дождитесь её или отмените'
          : 'Не удалось продолжить разбор: ' + err.message;
      })
      .then(stLoadImports);
  }

  // --- Мои форматы ---

  function stLoadProfiles() {
    stApi('GET', '/api/ai/statement-profiles').then(function (data) {
      if (!data) return;
      stProfiles = data.profiles || [];
      stRenderProfileOptions();
      stRenderOwn();
    }, function () {
      stProfiles = stProfiles || [];
    });
  }

  function stRenderOwn() {
    var el = document.getElementById('st-own');
    if (!el) return;
    var own = (stProfiles || []).filter(function (p) { return p.kind === 'own'; });
    if (!own.length) {
      el.innerHTML = '';
      return;
    }
    var details = el.querySelector('details');
    var open = (details && details.open) || !!stRename || !!stConfirmProfileDelete;
    el.innerHTML =
      '<details class="st-own"' + (open ? ' open' : '') + '>' +
      '<summary>Мои форматы · ' + own.length + '</summary>' +
      own.map(function (p) {
        var actions;
        var name = '<span class="st-own-name">' + escapeHtml(p.name) + '</span>';
        if (stRename && stRename.id === p.id) {
          name = '<input type="text" class="st-own-input" id="st-own-input" maxlength="100" value="' + escapeHtml(stRename.name) + '">';
          actions = '<button type="button" class="btn-chip" data-own-save>Сохранить</button>' +
            '<button type="button" class="btn-chip" data-own-cancel>Отмена</button>';
        } else if (stConfirmProfileDelete === p.id) {
          actions = '<span class="st-confirm-text">Удалить формат вместе с примерами?</span>' +
            '<button type="button" class="btn-chip access-danger" data-own-del-yes="' + escapeHtml(p.id) + '">Да, удалить</button>' +
            '<button type="button" class="btn-chip" data-own-cancel>Нет</button>';
        } else {
          actions = '<button type="button" class="btn-chip" data-own-rename="' + escapeHtml(p.id) + '">Переименовать</button>' +
            '<button type="button" class="btn-chip" data-own-del="' + escapeHtml(p.id) + '">Удалить</button>';
        }
        var n = p.examples || 0;
        return '<div class="st-own-row">' + name +
          '<span class="st-own-meta">' + n + ' ' + pluralRu(n, ['пример', 'примера', 'примеров']) + '</span>' +
          '<span class="st-own-actions">' + actions + '</span></div>';
      }).join('') +
      '<p class="sub st-own-hint">Свой формат появляется, когда вы исправляете сумму, дату или направление строки: ' +
      'исправленные строки становятся примерами для следующих выписок того же формата.</p>' +
      '</details>';
    var input = document.getElementById('st-own-input');
    if (input) {
      input.focus();
      input.addEventListener('input', function () { stRename.name = input.value; });
      input.addEventListener('keydown', function (ev) {
        if (ev.key === 'Enter') stSaveRename();
        if (ev.key === 'Escape') {
          stRename = null;
          stRenderOwn();
        }
      });
    }
  }

  function stSaveRename() {
    var r = stRename;
    if (!r || !r.name.trim()) return;
    stApi('PATCH', '/api/ai/statement-profiles/' + encodeURIComponent(r.id), { name: r.name.trim() })
      .then(function () {
        stRename = null;
        stLoadProfiles();
      }, function (err) {
        stRename = null;
        stListNotice = 'Не удалось переименовать формат: ' + err.message;
        stRenderList();
        stRenderOwn();
      });
  }

  function stDeleteProfile(id) {
    stConfirmProfileDelete = null;
    stApi('DELETE', '/api/ai/statement-profiles/' + encodeURIComponent(id))
      .then(function () {}, function (err) {
        if (err.status !== 404) {
          stListNotice = 'Не удалось удалить формат: ' + err.message;
          stRenderList();
        }
      })
      .then(stLoadProfiles);
  }

  // Делегирование на весь раздел: контейнеры перерисовываются, а обработчики
  // остаются на корне (#st-root живёт, пока открыты «Отчёты»).
  function stWireSection(root) {
    if (root.getAttribute('data-wired') === 'list') return;
    root.setAttribute('data-wired', 'list');
    root.addEventListener('input', function (ev) {
      if (stDetail || !stForm) return;
      if (ev.target.id === 'st-text') {
        stForm.text = ev.target.value;
        stUpdateFormState();
      }
    });
    root.addEventListener('change', function (ev) {
      if (stDetail || !stForm) return;
      var t = ev.target;
      if (t.id === 'st-wallet') stForm.walletUuid = t.value;
      else if (t.id === 'st-profile') {
        stForm.profile = t.value;
        stSetPref(ST_PROFILE_KEY, t.value);
      } else if (t.id === 'st-file') {
        var file = t.files && t.files[0];
        if (!file) return;
        var problem = stFileProblem(file);
        stForm.file = problem ? null : file;
        stForm.error = problem;
        stRenderForm();
        return;
      } else return;
      stUpdateFormState();
    });
    root.addEventListener('click', function (ev) {
      if (stDetail) return;
      var t = ev.target.closest('button');
      if (!t) return;
      var mode = t.getAttribute('data-st-mode');
      if (mode) {
        stForm.mode = mode;
        stForm.error = '';
        stRenderForm();
        return;
      }
      if (t.id === 'st-submit') return stSubmit();
      if (t.hasAttribute('data-st-open')) return stOpenImport(t.getAttribute('data-st-open'));
      if (t.hasAttribute('data-st-retry')) return stRetryImport(t.getAttribute('data-st-retry'));
      if (t.hasAttribute('data-st-del')) {
        stConfirmDelete = t.getAttribute('data-st-del');
        return stRenderList();
      }
      if (t.hasAttribute('data-st-del-no')) {
        stConfirmDelete = null;
        return stRenderList();
      }
      if (t.hasAttribute('data-st-del-yes')) return stDeleteImport(t.getAttribute('data-st-del-yes'));
      if (t.hasAttribute('data-own-rename')) {
        var id = t.getAttribute('data-own-rename');
        var p = (stProfiles || []).filter(function (x) { return x.id === id; })[0];
        stRename = { id: id, name: p ? p.name : '' };
        stConfirmProfileDelete = null;
        return stRenderOwn();
      }
      if (t.hasAttribute('data-own-save')) return stSaveRename();
      if (t.hasAttribute('data-own-cancel')) {
        stRename = null;
        stConfirmProfileDelete = null;
        return stRenderOwn();
      }
      if (t.hasAttribute('data-own-del')) {
        stConfirmProfileDelete = t.getAttribute('data-own-del');
        stRename = null;
        return stRenderOwn();
      }
      if (t.hasAttribute('data-own-del-yes')) return stDeleteProfile(t.getAttribute('data-own-del-yes'));
    });
  }

  // --- Экран проверки (#/reports/ai/import/<id>, D1) ---
  //
  // stDetail: {id, data — ответ GET /imports/{id}, error, loading, timer,
  //   q — поиск, groups — {группа: выбрана}, selected — {row_id: true},
  //   limit — порция строк, saving — {row_id: правок в полёте},
  //   rowError — {row_id: {field, message}}, srcOpen — {row_id: true},
  //   queue — Promise последней правки (правки идут по одной, D5),
  //   rendered — что нарисовано в таблице, addLine — форма «Добавить как
  //   операцию», confirmWrite, write — {done, total, busy, error}, doneLine}

  function stShowImport(id) {
    if (stDetail && stDetail.id === id) return;
    if (stDetail) clearTimeout(stDetail.timer);
    stDetail = id ? {
      id: id,
      data: null,
      error: '',
      loading: false,
      timer: null,
      q: '',
      groups: { ready: true, needs_category: true, possible_duplicate: true, check: true },
      selected: {},
      limit: ST_PAGE,
      saving: {},
      rowError: {},
      srcOpen: {},
      queue: Promise.resolve(),
      rendered: null,
      addLine: null,
      confirmWrite: false,
      write: null,
      doneLine: '',
    } : null;
    stRender();
    if (!stDetail) stLoadImports();
  }

  // «Проверить» в списке — переход с записью в истории (и «← Назад», и
  // браузерное «Назад» возвращают к списку).
  function stOpenImport(id) {
    pushReportsHistory();
    stShowImport(id);
    pushReportsUrlState('ai');
    window.scrollTo(0, 0);
  }

  function stBackToList() {
    var top = reportsHistory[reportsHistory.length - 1];
    if (top && top.view === 'ai' && !top.aiImport) {
      goReportsBack();
      return;
    }
    stShowImport(null);
    pushReportsUrlState('ai');
  }

  function stLoadDetail(reconcile) {
    var d = stDetail;
    if (!d || !aiHas('statement_import')) return;
    clearTimeout(d.timer);
    d.loading = true;
    stApi('GET', stImportUrl(d.id) + (reconcile ? '?reconcile=1' : ''))
      .then(function (data) {
        if (stDetail !== d || !data) return;
        d.loading = false;
        d.error = '';
        d.data = data;
        if (data.status === 'ready' || data.status === 'done') stMarkSeen(d.id);
        stRenderDetail();
        if (ST_ACTIVE.indexOf(data.status) >= 0) {
          d.timer = setTimeout(function () { if (stDetail === d) stLoadDetail(false); }, 5000);
        }
      }, function (err) {
        if (stDetail !== d) return;
        d.loading = false;
        d.error = err.status === 404 ? 'Импорт не найден — он удалён или истёк' : 'Не удалось загрузить импорт: ' + err.message;
        stRenderDetail();
      });
  }

  function stWallet(d) {
    return d.data ? aiFindWallet(d.data.wallet_uuid) : null;
  }

  function stSymbol(d) {
    var w = stWallet(d);
    return w ? (w.symbol || w.iso_code) : '';
  }

  function stGroupIndex(g) {
    for (var i = 0; i < ST_GROUPS.length; i++) if (ST_GROUPS[i][0] === g) return i;
    return ST_GROUPS.length;
  }

  function stVisibleRows(d) {
    var q = d.q.trim().toLowerCase();
    var rows = (d.data.rows || []).filter(function (r) {
      if (!d.groups[r.group]) return false;
      if (!q) return true;
      return (r.description || '').toLowerCase().indexOf(q) >= 0 || (r.comment || '').toLowerCase().indexOf(q) >= 0;
    });
    // Группы — в порядке чипов, внутри группы — по дате (стабильно).
    return rows.map(function (r, i) { return { r: r, i: i }; }).sort(function (a, b) {
      var g = stGroupIndex(a.r.group) - stGroupIndex(b.r.group);
      if (g) return g;
      if (a.r.date !== b.r.date) return a.r.date < b.r.date ? -1 : 1;
      return a.i - b.i;
    }).map(function (x) { return x.r; });
  }

  function stVisibleUnparsed(d) {
    if (!d.groups.unparsed) return [];
    var q = d.q.trim().toLowerCase();
    return (d.data.unparsed || []).filter(function (u) { return !q || u.text.toLowerCase().indexOf(q) >= 0; });
  }

  // Строку можно править и выбирать: импорт ready, строка не записана и это расход.
  function stRowEditable(d, r) {
    return d.data.status === 'ready' && !r.committed && r.dir === 'expense';
  }

  function stCategoryOptionsHtml(r) {
    var cats = aiAccounts ? aiAccounts.categories : [];
    var suggested = null;
    if (!r.category_uuid && r.suggestion) {
      cats.forEach(function (c) { if (c.name === r.suggestion) suggested = c; });
    }
    var html = '<option value=""' + (r.category_uuid ? '' : ' selected') + '>' + (suggested ? '—' : 'Выберите категорию') + '</option>';
    if (suggested) {
      html += '<option value="' + escapeHtml(suggested.uuid) + '">' + escapeHtml(suggested.name) + ' · ИИ предлагает</option>';
    }
    var known = false;
    cats.forEach(function (c) {
      if (c === suggested) return;
      if (c.uuid === r.category_uuid) known = true;
      html += '<option value="' + escapeHtml(c.uuid) + '"' + (c.uuid === r.category_uuid ? ' selected' : '') + '>' +
        escapeHtml(c.name) + '</option>';
    });
    if (r.category_uuid && !known) {
      html += '<option value="' + escapeHtml(r.category_uuid) + '" selected>Категория в архиве</option>';
    }
    return html;
  }

  function stProblemText(d, r) {
    if (r.check) return ST_CHECK_TEXT[r.check] || r.check;
    if (r.decision === 'skip') return 'пропущена — не будет записана';
    if (r.match === 'imported' && r.group === 'imported') return 'уже импортировано из выписки раньше';
    if ((r.group === 'possible_duplicate' || r.group === 'exists') && r.match_candidates && r.match_candidates.length) {
      return 'похоже на: ' + r.match_candidates.map(function (c) {
        return formatDate(c.date) + ' ' + groupThousands(r.amount) + ' ' + stSymbol(d);
      }).join('; ');
    }
    if (r.group === 'exists') return 'отмечено как дубль';
    return '';
  }

  function stRowActionsHtml(d, r) {
    if (r.committed) return '<span class="st-mark-done">записано</span>';
    if (!stRowEditable(d, r)) return '';
    function btn(decision, label) {
      return '<button type="button" class="btn-chip" data-dec="' + decision + '">' + label + '</button>';
    }
    if (r.decision === 'skip') return btn('null', 'Вернуть');
    var html = '';
    if (r.group === 'possible_duplicate') html += btn('duplicate', 'Это дубль') + btn('include', 'Это новая');
    if (r.group === 'exists' || r.group === 'imported') html += btn('include', 'Всё равно записать');
    return html + btn('skip', 'Пропустить');
  }

  function stFieldId(rowId, field) {
    return 'st-f-' + rowId + '-' + field;
  }

  function stRowHtml(d, r) {
    var editable = stRowEditable(d, r);
    var off = editable ? '' : ' disabled';
    var err = d.rowError[r.row_id];
    var src = (r.lines || []).map(function (l) { return l.n + '| ' + l.text; }).join('\n');
    var problem = stProblemText(d, r);
    var cat;
    if (r.dir !== 'expense') {
      cat = '<span class="st-dir">' + (r.dir === 'income' ? 'доход' : 'перевод') + ' — не записывается</span>';
    } else {
      cat = '<select id="' + stFieldId(r.row_id, 'category') + '" data-f="category"' +
        (err && err.field === 'category' ? ' class="invalid"' : '') + off + '>' + stCategoryOptionsHtml(r) + '</select>' +
        (r.category_uuid && ST_SOURCE_TEXT[r.source] ? '<span class="st-cat-source">' + ST_SOURCE_TEXT[r.source] + '</span>' : '');
    }
    function invalid(field) { return err && err.field === field ? ' class="invalid"' : ''; }
    return '<div class="st-row' + (r.decision === 'skip' ? ' skipped' : '') + (r.committed ? ' committed' : '') +
      (d.selected[r.row_id] ? ' selected' : '') + ' st-g-' + r.group + '" role="row" data-row="' + escapeHtml(r.row_id) + '">' +
      '<span class="st-c-check"><input type="checkbox" data-sel aria-label="Выбрать строку"' +
      (d.selected[r.row_id] ? ' checked' : '') + off + '></span>' +
      '<span class="st-c-date"><input type="date" id="' + stFieldId(r.row_id, 'date') + '" data-f="date" max="' + isoDate(new Date()) +
      '" value="' + escapeHtml(r.date) + '"' + invalid('date') + off + '></span>' +
      '<span class="st-c-desc">' +
      '<span class="st-desc-line"><span class="st-desc" title="' + escapeHtml(src) + '">' + escapeHtml(r.description || '—') + '</span>' +
      (src ? '<button type="button" class="st-src-btn" data-src aria-label="Строка из выписки" title="Строка из выписки">i</button>' : '') +
      '</span>' +
      (d.srcOpen[r.row_id] ? '<pre class="st-src">' + escapeHtml(src) + '</pre>' : '') +
      '<input type="text" class="st-comment' + (err && err.field === 'comment' ? ' invalid' : '') + '" id="' +
      stFieldId(r.row_id, 'comment') + '" data-f="comment" maxlength="255" ' +
      'placeholder="Комментарий" value="' + escapeHtml(r.comment || '') + '"' + off + '>' +
      (problem ? '<span class="st-problem">' + escapeHtml(problem) + '</span>' : '') +
      (d.saving[r.row_id] ? '<span class="st-saving">сохраняю…</span>' : '') +
      (err ? '<span class="st-row-error">' + escapeHtml(err.message) + '</span>' : '') +
      '</span>' +
      '<span class="st-c-amount"><input type="text" inputmode="decimal" id="' + stFieldId(r.row_id, 'amount') + '" data-f="amount" value="' +
      escapeHtml(r.amount) + '"' + invalid('amount') + off + '><span class="st-sym">' + escapeHtml(stSymbol(d)) + '</span></span>' +
      '<span class="st-c-cat">' + cat + '</span>' +
      '<span class="st-c-act">' + stRowActionsHtml(d, r) + '</span>' +
      '</div>';
  }

  function stUnparsedHtml(d, u) {
    var a = d.addLine;
    if (a && a.n === u.n) {
      return '<div class="st-row st-unparsed st-adding" role="row" data-line="' + u.n + '">' +
        '<pre class="st-src">' + escapeHtml(u.n + '| ' + u.text) + '</pre>' +
        '<div class="st-add-grid">' +
        '<label class="ai-field">Дата<input type="date" id="st-add-date" max="' + isoDate(new Date()) + '" value="' + escapeHtml(a.date) + '"></label>' +
        '<label class="ai-field">Сумма<input type="text" inputmode="decimal" id="st-add-amount" value="' + escapeHtml(a.amount) + '"></label>' +
        '<label class="ai-field">Категория<select id="st-add-category">' +
        stCategoryOptionsHtml({ category_uuid: a.category, suggestion: null }) + '</select></label>' +
        '<label class="ai-field ai-field-wide">Описание<input type="text" id="st-add-desc" value="' + escapeHtml(a.description) + '"></label>' +
        '</div>' +
        (a.error ? '<p class="err">' + escapeHtml(a.error) + '</p>' : '') +
        '<div class="st-add-actions">' +
        '<button type="button" class="btn" data-add-save>' + (a.busy ? 'Добавляю…' : 'Добавить') + '</button>' +
        '<button type="button" class="btn btn-secondary" data-add-cancel>Отмена</button>' +
        '</div></div>';
    }
    return '<div class="st-row st-unparsed" role="row" data-line="' + u.n + '">' +
      '<pre class="st-src">' + escapeHtml(u.n + '| ' + u.text) + '</pre>' +
      (d.data.status === 'ready' ? '<button type="button" class="btn-chip" data-add-line="' + u.n + '">Добавить как операцию</button>' : '') +
      '</div>';
  }

  function stRenderDetail() {
    var el = document.getElementById('st-detail');
    var d = stDetail;
    if (!el || !d) return;
    var back = '<button type="button" class="btn-chip st-back" data-st-back>← К импортам</button>';
    if (d.error) {
      el.innerHTML = back + reportsErrorHtml(d.error);
      stWireDetail(el);
      return;
    }
    if (!d.data) {
      el.innerHTML = back + '<p class="sub">Загрузка…</p>';
      stWireDetail(el);
      return;
    }
    var imp = d.data;
    var wallet = stWallet(d);
    var profile = stProfileText(imp);
    var head =
      back +
      '<div class="st-d-head">' +
      '<h2>' + escapeHtml(imp.source_name || 'Текст') + '</h2>' +
      '<div class="st-import-meta">' + escapeHtml([wallet ? wallet.name : '', stCreatedText(imp.created_at)].filter(Boolean).join(' · ')) + '</div>' +
      (profile ? '<div class="st-import-meta">' + escapeHtml(profile) + '</div>' : '') +
      (imp.profile_detect === 'none' || imp.profile_detect === 'ambiguous'
        ? '<div class="st-import-meta st-hint">Исправленные строки станут примерами для следующей выписки этого формата</div>' : '') +
      '</div>';
    if (imp.status !== 'ready' && imp.status !== 'done') {
      var p = imp.progress;
      el.innerHTML = head +
        '<div class="ai-status' + (imp.status === 'failed' ? ' ai-status-fail' : '') + '">' +
        (ST_ACTIVE.indexOf(imp.status) >= 0 ? '<span class="ai-spinner" aria-hidden="true"></span>' : '') +
        escapeHtml(stStatusText(imp)) + '</div>' +
        (imp.status === 'extracting' && p && p.total > 0
          ? '<div class="st-progress"><span style="width:' + Math.round(100 * p.done / p.total) + '%"></span></div>' : '') +
        (ST_ACTIVE.indexOf(imp.status) >= 0 ? '<p class="sub">Экран обновится сам, когда разбор закончится.</p>' : '');
      stWireDetail(el);
      return;
    }
    el.innerHTML = head +
      (imp.reconciled === false
        ? '<div class="ai-status ai-status-fail"><span>Не удалось сверить с внесёнными операциями — дубли не отмечены</span>' +
          '<button type="button" class="btn btn-secondary" data-reconcile>Сверить ещё раз</button></div>' : '') +
      (d.doneLine ? '<div class="ai-status ai-status-done">' + escapeHtml(d.doneLine) + '</div>' : '') +
      '<div class="st-chips" id="st-chips"></div>' +
      '<input type="search" class="st-search" id="st-search" placeholder="Поиск по описанию" value="' + escapeHtml(d.q) + '">' +
      '<div class="st-table" role="table">' +
      '<div class="st-row st-head" role="row">' +
      '<span class="st-c-check"><input type="checkbox" id="st-select-all" aria-label="Выбрать все видимые"></span>' +
      '<span class="st-c-date">Дата</span><span class="st-c-desc">Описание</span><span class="st-c-amount">Сумма</span>' +
      '<span class="st-c-cat">Категория</span><span class="st-c-act"></span>' +
      '</div>' +
      '<div id="st-rows"></div>' +
      '</div>' +
      '<div class="st-footbar" id="st-footbar"></div>';
    d.rendered = null;
    stRenderChips();
    stRenderRows();
    stRenderFoot();
    stWireDetail(el);
  }

  function stRenderChips() {
    var d = stDetail;
    var el = document.getElementById('st-chips');
    if (!el || !d || !d.data) return;
    var groups = d.data.groups || {};
    el.innerHTML = ST_GROUPS.map(function (g) {
      var n = groups[g[0]] || 0;
      return '<button type="button" class="ops-chip st-chip' + (d.groups[g[0]] ? ' active' : '') + (n ? '' : ' empty') +
        '" data-g="' + g[0] + '" aria-pressed="' + (d.groups[g[0]] ? 'true' : 'false') + '">' +
        escapeHtml(g[1]) + ' <b>' + n + '</b></button>';
    }).join('');
  }

  // Таблица: если набор видимых строк не изменился — заменяются только
  // изменившиеся строки (правка соседней строки не сбивает ввод в этой),
  // иначе — перерисовка целиком с возвратом фокуса в то же поле.
  function stRenderRows(full) {
    var d = stDetail;
    var el = document.getElementById('st-rows');
    if (!el || !d || !d.data) return;
    var all = stVisibleRows(d);
    var rows = all.slice(0, d.limit);
    var unparsed = stVisibleUnparsed(d);
    var ids = rows.map(function (r) { return r.row_id; });
    var html = {};
    rows.forEach(function (r) { html[r.row_id] = stRowHtml(d, r); });
    var tail = (all.length > rows.length
      ? '<button type="button" class="btn btn-secondary st-more" data-more>Показать ещё (' + (all.length - rows.length) + ')</button>' : '') +
      (unparsed.length ? '<div class="st-unparsed-title">Не разобрано — строки выписки с суммой, которых нет среди операций</div>' +
        unparsed.map(function (u) { return stUnparsedHtml(d, u); }).join('') : '') +
      (!rows.length && !unparsed.length ? '<p class="sub st-empty">Нет строк под выбранными группами.</p>' : '');
    var prev = d.rendered;
    var active = document.activeElement;
    var activeId = active && active.id && active.id.indexOf('st-') === 0 ? active.id : '';
    if (!full && prev && prev.ids.join(',') === ids.join(',') && prev.tail === tail) {
      ids.forEach(function (id) {
        if (prev.html[id] === html[id]) return;
        var old = el.querySelector('[data-row="' + id + '"]');
        if (old) old.outerHTML = html[id];
      });
    } else {
      el.innerHTML = ids.map(function (id) { return html[id]; }).join('') + tail;
    }
    d.rendered = { ids: ids, html: html, tail: tail };
    if (activeId && document.activeElement !== active) {
      var again = document.getElementById(activeId);
      if (again) again.focus();
    }
    var all2 = document.getElementById('st-select-all');
    if (all2) {
      var selectable = rows.filter(function (r) { return stRowEditable(d, r); });
      all2.checked = selectable.length > 0 && selectable.every(function (r) { return d.selected[r.row_id]; });
      all2.disabled = !selectable.length;
    }
  }

  function stSelectedIds(d) {
    return Object.keys(d.selected).filter(function (id) { return d.selected[id]; });
  }

  function stOperationsTotal(d, ops) {
    var cents = 0;
    ops.forEach(function (o) { cents += Math.round(parseFloat(o.amount) * 100); });
    return fmtNative((cents / 100).toFixed(2), stSymbol(d));
  }

  function stRenderFoot() {
    var d = stDetail;
    var el = document.getElementById('st-footbar');
    if (!el || !d || !d.data) return;
    var ops = d.data.operations || [];
    var selected = stSelectedIds(d);
    var html = '';
    if (selected.length) {
      html += '<div class="st-bulk">' +
        '<span class="st-bulk-count">Выбрано ' + selected.length + ':</span>' +
        '<select id="st-bulk-category" aria-label="Категория для выбранных">' +
        stCategoryOptionsHtml({ category_uuid: null, suggestion: null }).replace('Выберите категорию', 'Категория…') + '</select>' +
        '<button type="button" class="btn-chip" data-bulk-skip>Пропустить</button>' +
        '<button type="button" class="btn-chip" data-bulk-clear>Снять выбор</button>' +
        '</div>';
    }
    var w = d.write;
    var wallet = stWallet(d);
    if (d.confirmWrite) {
      var unparsed = (d.data.groups || {}).unparsed || 0;
      html += '<div class="st-confirm">' +
        '<p>Записать ' + ops.length + ' ' + pluralRu(ops.length, ['операцию', 'операции', 'операций']) +
        ' в «' + escapeHtml(wallet ? wallet.name : '') + '» на сумму ' + stOperationsTotal(d, ops) + '?</p>' +
        (unparsed ? '<p class="st-confirm-warn">Ещё ' + unparsed + ' ' + pluralRu(unparsed, ['строка', 'строки', 'строк']) +
          ' выписки не разобрано — <button type="button" class="link-btn" data-show-unparsed>посмотреть</button></p>' : '') +
        '<div class="st-add-actions"><button type="button" class="btn" data-write-yes>Записать</button>' +
        '<button type="button" class="btn btn-secondary" data-write-no>Отмена</button></div>' +
        '</div>';
    } else if (w && (w.busy || w.error)) {
      html += '<div class="st-write-status' + (w.error ? ' fail' : '') + '">' +
        (w.busy ? '<span class="ai-spinner" aria-hidden="true"></span>' : '') +
        '<span>Записано ' + w.done + ' из ' + w.total + (w.error ? '. Не удалось записать остальные — ' + escapeHtml(w.error) : '') + '</span>' +
        (w.error ? '<button type="button" class="btn" data-write-retry>Повторить</button>' : '') +
        '</div>';
    } else if (d.data.status === 'ready') {
      html += '<button type="button" class="btn st-write-btn" data-write' + (ops.length ? '' : ' disabled') + '>Записать ' + ops.length + '</button>';
    }
    el.innerHTML = html;
    el.hidden = !html;
  }

  function stAfterData(d) {
    var rows = d.data.rows || [];
    var alive = {};
    rows.forEach(function (r) { if (stRowEditable(d, r)) alive[r.row_id] = true; });
    Object.keys(d.selected).forEach(function (id) { if (!alive[id]) delete d.selected[id]; });
    stRenderChips();
    stRenderRows();
    stRenderFoot();
  }

  // Правки строк (D5): по одной в полёте — следующая ждёт ответа предыдущей,
  // ответ сервера — источник истины (в нём и соседние строки по правилу).
  // Ошибка — значение откатывается (строка рисуется из прежнего ответа).
  function stPatchRows(patches, field) {
    var d = stDetail;
    if (!d || !patches.length) return;
    var ids = patches.map(function (p) { return p.row_id; });
    ids.forEach(function (id) {
      d.saving[id] = (d.saving[id] || 0) + 1;
      delete d.rowError[id];
    });
    stRenderRows();
    d.queue = d.queue
      .then(function () { return stApi('PATCH', stImportUrl(d.id) + '/rows', { rows: patches }); })
      .then(function (data) {
        ids.forEach(function (id) { d.saving[id] -= 1; });
        if (stDetail !== d || !data) return;
        d.data = data;
        stAfterData(d);
      }, function (err) {
        ids.forEach(function (id) { d.saving[id] -= 1; });
        if (stDetail !== d) return;
        var code = err.body && err.body.error;
        var message = ST_PATCH_ERROR[code] || 'Не сохранилось: ' + err.message;
        ids.forEach(function (id) { d.rowError[id] = { field: field, message: message }; });
        if (err.status === 409) stLoadDetail(false);
        stRenderRows(true);
      });
  }

  function stNormalizeAmount(value) {
    var a = value.replace(/[\s ]/g, '').replace(',', '.');
    return /^\d+(\.\d{1,2})?$/.test(a) && parseFloat(a) > 0 ? a : '';
  }

  function stEditRow(rowId, field, value) {
    var d = stDetail;
    var patch = { row_id: rowId };
    if (field === 'amount') {
      var amount = stNormalizeAmount(value);
      if (!amount) {
        d.rowError[rowId] = { field: 'amount', message: ST_PATCH_ERROR.bad_amount };
        stRenderRows(true);
        return;
      }
      patch.amount = amount;
    } else if (field === 'date') {
      if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) {
        d.rowError[rowId] = { field: 'date', message: 'Укажите дату' };
        stRenderRows(true);
        return;
      }
      patch.date = value;
    } else if (field === 'category') {
      patch.category_uuid = value || null;
    } else if (field === 'comment') {
      patch.comment = value.trim() ? value.trim().slice(0, 255) : null;
    }
    stPatchRows([patch], field);
  }

  function stAddRow() {
    var d = stDetail;
    var a = d && d.addLine;
    if (!a || a.busy) return;
    var amount = stNormalizeAmount(a.amount);
    if (!amount) a.error = ST_PATCH_ERROR.bad_amount;
    else if (!/^\d{4}-\d{2}-\d{2}$/.test(a.date)) a.error = 'Укажите дату';
    else a.error = '';
    if (a.error) {
      stRenderRows(true);
      return;
    }
    a.busy = true;
    stRenderRows(true);
    var body = { line: a.n, amount: amount, date: a.date, description: a.description.trim() };
    if (a.category) body.category_uuid = a.category;
    d.queue = d.queue
      .then(function () { return stApi('POST', stImportUrl(d.id) + '/rows', body); })
      .then(function (data) {
        if (stDetail !== d || !data) return;
        d.addLine = null;
        d.data = data;
        stAfterData(d);
      }, function (err) {
        if (stDetail !== d) return;
        a.busy = false;
        a.error = ST_PATCH_ERROR[err.body && err.body.error] || 'Не удалось добавить: ' + err.message;
        stRenderRows(true);
      });
  }

  // POST /sync/push одной пачкой (тот же путь и та же таблица исходов, что у
  // траты текстом, см. aiPush). batch_id — новый на каждую отправку:
  // идемпотентность держится на uuid операций (op_uuid импорта, D6).
  function stPush(batch, retriedDevice) {
    return apiFetch('/sync/push', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        batch_id: uuidV4(),
        device_name: 'Веб-браузер',
        changes: {
          operation: batch.map(function (o) {
            return { uuid: o.uuid, date: o.date, acc_fr_uuid: o.acc_fr_uuid, acc_to_uuid: o.acc_to_uuid, amount: o.amount, comment: o.comment };
          }),
        },
      }),
    }).then(function (res) {
      if (res.status === 401) {
        renderLogin();
        var stop = new Error('login');
        stop.login = true;
        throw stop;
      }
      return res.json().catch(function () { return {}; }).then(function (data) {
        if (res.ok) return;
        var code = data && data.error ? data.error : '';
        if (res.status === 403 && code === 'device_required') {
          if (retriedDevice) throw new Error('перезайдите, чтобы записывать траты из браузера');
          return fetch('/auth/refresh', { method: 'POST', credentials: 'include' }).then(function () {
            return stPush(batch, true);
          });
        }
        if (res.status >= 500) throw new Error('попробуйте ещё раз');
        throw new Error(AI_PUSH_ERROR_TEXT[code] || code || 'HTTP ' + res.status);
      });
    }, function () {
      throw new Error('попробуйте ещё раз');
    });
  }

  function stPushBatches(d, ops) {
    if (!ops.length) return Promise.resolve();
    var batch = ops.slice(0, ST_PUSH_BATCH);
    return stPush(batch, false)
      .then(function () {
        return stApi('POST', stImportUrl(d.id) + '/committed', { row_ids: batch.map(function (o) { return o.row_id; }) })
          .catch(function () { throw new Error('попробуйте ещё раз'); });
      })
      .then(function (data) {
        if (!data) {
          var stop = new Error('login');
          stop.login = true;
          throw stop;
        }
        d.write.done += batch.length;
        if (stDetail === d) {
          d.data = data;
          stAfterData(d);
        }
        return stPushBatches(d, ops.slice(ST_PUSH_BATCH));
      });
  }

  // «Записать N» (D6): перечитать импорт, записать его готовые операции
  // пачками по 50 с /committed после каждой. «Повторить» после сбоя —
  // та же функция: импорт отдаёт только ещё не отмеченные строки.
  function stWrite() {
    var d = stDetail;
    if (!d || (d.write && d.write.busy)) return;
    d.confirmWrite = false;
    d.doneLine = '';
    var done = d.write ? d.write.done : 0;
    d.write = { done: done, total: done, busy: true, error: '' };
    stRenderFoot();
    d.queue = d.queue
      .then(function () { return stApi('GET', stImportUrl(d.id)); })
      .then(function (data) {
        if (!data) {
          var stop = new Error('login');
          stop.login = true;
          throw stop;
        }
        d.data = data;
        var ops = data.operations || [];
        d.write.total = d.write.done + ops.length;
        if (stDetail === d) stAfterData(d);
        return stPushBatches(d, ops);
      })
      .then(function () {
        var written = d.write.done;
        var left = (d.data.rows || []).filter(function (r) { return !r.committed; }).length;
        d.write = null;
        d.doneLine = 'Готово: записано ' + written + ', пропущено ' + left;
        // Записанное должно появиться в отчётах без F5 — как у траты текстом.
        reportsCache = {};
        refreshPeriod();
        if (stDetail === d) stRenderDetail();
      }, function (err) {
        if (err.login) return;
        d.write.busy = false;
        d.write.error = err.message || 'попробуйте ещё раз';
        if (stDetail === d) stRenderFoot();
      });
  }

  function stWireDetail(el) {
    var root = document.getElementById('st-root');
    if (!root || root.getAttribute('data-wired-detail') === '1') return;
    root.setAttribute('data-wired-detail', '1');
    root.addEventListener('click', function (ev) {
      var d = stDetail;
      if (!d) return;
      var t = ev.target.closest('button');
      if (!t) return;
      if (t.hasAttribute('data-st-back')) return stBackToList();
      if (!d.data) return;
      var rowEl = t.closest('[data-row]');
      var rowId = rowEl ? rowEl.getAttribute('data-row') : '';
      if (t.hasAttribute('data-g')) {
        var g = t.getAttribute('data-g');
        d.groups[g] = !d.groups[g];
        d.limit = ST_PAGE;
        stRenderChips();
        stRenderRows(true);
        return;
      }
      if (t.hasAttribute('data-reconcile')) return stLoadDetail(true);
      if (t.hasAttribute('data-src') && rowId) {
        d.srcOpen[rowId] = !d.srcOpen[rowId];
        return stRenderRows();
      }
      if (t.hasAttribute('data-dec') && rowId) {
        var dec = t.getAttribute('data-dec');
        return stPatchRows([{ row_id: rowId, decision: dec === 'null' ? null : dec }], 'decision');
      }
      if (t.hasAttribute('data-more')) {
        d.limit += ST_PAGE;
        return stRenderRows(true);
      }
      if (t.hasAttribute('data-add-line')) {
        var n = parseInt(t.getAttribute('data-add-line'), 10);
        var line = (d.data.unparsed || []).filter(function (u) { return u.n === n; })[0];
        d.addLine = { n: n, date: '', amount: '', category: '', description: line ? line.text.trim() : '', error: '', busy: false };
        return stRenderRows(true);
      }
      if (t.hasAttribute('data-add-cancel')) {
        d.addLine = null;
        return stRenderRows(true);
      }
      if (t.hasAttribute('data-add-save')) return stAddRow();
      if (t.hasAttribute('data-bulk-skip')) {
        return stPatchRows(stSelectedIds(d).map(function (id) { return { row_id: id, decision: 'skip' }; }), 'decision');
      }
      if (t.hasAttribute('data-bulk-clear')) {
        d.selected = {};
        stRenderRows();
        return stRenderFoot();
      }
      if (t.hasAttribute('data-write')) {
        d.confirmWrite = true;
        return stRenderFoot();
      }
      if (t.hasAttribute('data-write-no')) {
        d.confirmWrite = false;
        return stRenderFoot();
      }
      if (t.hasAttribute('data-write-yes') || t.hasAttribute('data-write-retry')) return stWrite();
      if (t.hasAttribute('data-show-unparsed')) {
        d.confirmWrite = false;
        d.groups = { unparsed: true };
        stRenderChips();
        stRenderRows(true);
        stRenderFoot();
        var rowsEl = document.getElementById('st-rows');
        if (rowsEl) rowsEl.scrollIntoView({ block: 'start' });
      }
    });
    root.addEventListener('input', function (ev) {
      var d = stDetail;
      if (!d) return;
      var t = ev.target;
      if (t.id === 'st-search') {
        d.q = t.value;
        d.limit = ST_PAGE;
        stRenderRows(true);
        return;
      }
      if (d.addLine && t.id && t.id.indexOf('st-add-') === 0) {
        var key = { 'st-add-date': 'date', 'st-add-amount': 'amount', 'st-add-category': 'category', 'st-add-desc': 'description' }[t.id];
        if (key) d.addLine[key] = t.value;
      }
    });
    root.addEventListener('change', function (ev) {
      var d = stDetail;
      if (!d || !d.data) return;
      var t = ev.target;
      if (t.id === 'st-add-category' && d.addLine) {
        d.addLine.category = t.value;
        return;
      }
      if (t.id === 'st-select-all') {
        stVisibleRows(d).slice(0, d.limit).forEach(function (r) {
          if (stRowEditable(d, r)) {
            if (t.checked) d.selected[r.row_id] = true;
            else delete d.selected[r.row_id];
          }
        });
        stRenderRows();
        stRenderFoot();
        return;
      }
      if (t.id === 'st-bulk-category') {
        if (!t.value) return;
        stPatchRows(stSelectedIds(d).map(function (id) { return { row_id: id, category_uuid: t.value }; }), 'category');
        return;
      }
      var rowEl = t.closest('[data-row]');
      if (!rowEl) return;
      var rowId = rowEl.getAttribute('data-row');
      if (t.hasAttribute('data-sel')) {
        if (t.checked) d.selected[rowId] = true;
        else delete d.selected[rowId];
        stRenderRows();
        stRenderFoot();
        return;
      }
      var field = t.getAttribute('data-f');
      if (field) stEditRow(rowId, field, t.value);
    });
  }

  // Сайдбар-навигация "Отчётов" — группы/пункты взяты из VIEWS в
  // Design/.../Отчёты - веб (офлайн).html (11 пунктов в 4 группах: Обзор ·
  // Куда уходит · Когда · Насколько изменилось — плюс пятая, "Кошелёк", ниже).
  // Реальные данные у нас сегодня под 'over' (Баланс/Доход/Расход), 'ops'
  // (GET /api/reports/operations), 'struct' (GET /api/reports/expense-structure),
  // 'cats' (переиспользует /api/reports/operations, см. refreshCategories) и
  // 'wal' (GET /api/reports/wallet-turnover + переиспользование /balance, см.
  // refreshWalletBalances) — остальные пять НЕ убраны (виден масштаб
  // задуманного отчёта), а задизейблены: без onClick, .nav-item:disabled,
  // бейдж "скоро".
  var REPORTS_NAV = [
    { group: '', items: [['over', 'Обзор', true], ['ops', 'Список операций', true]] },
    { group: 'Куда уходит', items: [
        ['struct', 'Структура расходов', true],
        ['cats', 'Категории во времени', true],
        ['places', 'Места и подписки', false],
    ] },
    { group: 'Когда', items: [
        ['cal', 'Календарь трат', false],
        ['rhythm', 'Ритм недели', false],
        ['pace', 'Темп месяца', false],
    ] },
    { group: 'Насколько изменилось', items: [
        ['dyn', 'Динамика', true],
        ['change', 'Что изменилось', false],
        ['check', 'Средний чек и частота', false],
    ] },
    { group: 'Кошелёк', items: [
        ['wal', 'Кошельки и остатки', true],
        ['cap', 'Капитал', true],
        ['cur', 'Курсы валют', true],
        ['acc', 'Доступ и приглашения', true],
        ['icons', 'Иконки', true],
    ] },
    // id — группа скрыта, пока не ответил GET /api/ai/status (см. refreshAiStatus).
    { group: 'ИИ', id: 'nav-group-ai', items: [['ai', 'ИИ', true]] },
    // Так же скрыта до GET /api/docs/status (см. refreshDocsStatus).
    { group: 'Справка', id: 'nav-group-docs', items: [['docs', 'Справка', true]] },
  ];

  // Экраны, реально построенные в разметке renderReports() (см. ниже) —
  // общий список для switchReportsView (что скрывать/показывать) и
  // parseReportsHash (что можно восстановить из hash при F5). Раньше это
  // был буквальный литерал в обоих местах — вынесен один раз, чтобы
  // добавление вкладки не значило править два места по отдельности.
  var REPORTS_BUILT_VIEWS = ['over', 'ops', 'struct', 'dyn', 'cats', 'wal', 'cap', 'cur', 'acc', 'icons', 'ai', 'docs'];

  // Нижняя панель вкладок мобильной раскладки (по прямому запросу — "меню
  // неудобное: открыл — занимает много места, надо прятать ещё одним нажатием").
  // [вид, подпись, path иконки 24×24]. Остальные пункты — в шторке "Ещё": это
  // тот же сайдбар, на телефоне он выезжает снизу без пунктов, уже стоящих в
  // панели, и без "скоро" (см. style.css, .in-tabbar).
  var MOBILE_TABS = [
    ['over', 'Обзор', 'M4 4h7v7H4zM13 4h7v7h-7zM4 13h7v7H4zM13 13h7v7h-7z'],
    ['ops', 'Операции', 'M9 6h11M9 12h11M9 18h11M4.5 6h.01M4.5 12h.01M4.5 18h.01'],
    ['struct', 'Структура', 'M12 3a9 9 0 1 0 9 9h-9zM15 3.5a9 9 0 0 1 5.5 5.5H15z'],
    ['dyn', 'Динамика', 'M3 20h18M5 16l4-5 4 3 6-8']
  ];

  function isMobileTabView(view) {
    return MOBILE_TABS.some(function (t) { return t[0] === view; });
  }

  function mobileTabbarHtml() {
    function tab(attrs, label, path) {
      return '<button type="button" class="mobile-tab" ' + attrs + '>' +
        '<svg viewBox="0 0 24 24" width="22" height="22" aria-hidden="true"><path d="' + path + '" fill="none" ' +
        'stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>' +
        '<span>' + escapeHtml(label) + '</span></button>';
    }
    return '<nav class="mobile-tabbar" id="mobile-tabbar">' +
      MOBILE_TABS.map(function (t) { return tab('data-tab="' + t[0] + '"', t[1], t[2]); }).join('') +
      tab('id="mobile-more-btn"', 'Ещё', 'M5 12h.01M12 12h.01M19 12h.01') +
      '</nav>';
  }
  // Вкладки, не зависящие ни от периода, ни от валюты эквивалента (см.
  // refreshCurrencyPairs/refreshAccess/refreshIcons — зовутся вне
  // refreshPeriod) — на них фильтр в шапке скрыт (switchReportsView).
  var PERIOD_FREE_VIEWS = ['cur', 'acc', 'icons', 'ai', 'docs'];

  // Заголовок/подзаголовок каждого пункта — то же TITLES из дизайна, но
  // текстом только у реализованных: у отключённых пунктов заголовок никогда
  // не показывается (на них нельзя переключиться).
  var REPORTS_TITLES = {
    over: ['Обзор', 'Сколько уходит, куда и как это менялось'],
    ops: ['Список операций', 'Каждая проводка периода: поиск, фильтры и разбор одной операции'],
    struct: ['Структура расходов', 'Доли категорий в расходе за период и сдвиг долей'],
    dyn: ['Динамика', 'Расход и доход период за периодом, выбранный бакет — по категориям'],
    cats: ['Категории во времени', 'Крупнейшие категории расхода — тренд по выбранному периоду'],
    wal: ['Кошельки и остатки', 'Где лежат деньги: остаток каждого счёта, обороты за период и валюты'],
    cap: ['Капитал', 'Во что вложены деньги и как менялась оценка'],
    cur: ['Курсы валют', 'Валютные пары и история их курса — добавление, изменение и удаление вручную'],
    acc: ['Доступ и приглашения', 'Кто видит этот кошелёк и как пригласить ещё одного человека'],
    icons: ['Иконки', 'Все иконки, доступные этому кошельку: общий набор и добавленные вами'],
    ai: ['ИИ', 'Трата своими словами и импорт выписки банка — проверьте и запишите'],
    docs: ['Справка', 'Спросите своими словами, как устроено приложение, — ответ по его описанию'],
  };

  // Текущий пункт навигации — модульная переменная (тот же приём, что и
  // currentUser): переключается кликом по пункту, читается при построении
  // и обновлении разметки, без повторного похода в сеть (обе вкладки грузят
  // данные один раз, при первом открытии "Отчётов" — см. конец renderReports()).
  var reportsView = 'over';

  // "Назад" (по прямому запросу) — стек состояний "Отчётов", а не просто
  // "прошлая вкладка": период/валюта — ОДНИ поля в шапке на все вкладки
  // разом (см. renderReports); режим сравнения (`#structure-cmp-mode`) —
  // тоже ОДНО общее значение на все вкладки (его самого читают "Обзор" и
  // "Структура", просто её виджет физически переехал внутрь "Обзора" — к
  // "Что изменилось", см. там же), поэтому переход "с деталями" (кнопки
  // "Вся динамика →"/"Подробно →", клик по столбцу "Обзора" — см.
  // goToMonthDetail) обязан запомнить фильтр ДО перехода, а не только
  // вкладку: пока пользователь разглядывал детали, он мог успеть поменять
  // период/валюту/сравнение прямо там, и "Назад" должен вернуть то, что
  // было, а не то, что оказалось в полях к моменту клика по "Назад".
  //
  // Обычные клики по пунктам сайдбара НЕ пушат сюда — это осознанный прямой
  // переход пользователя, не "детализация", и вести историю по каждому
  // такому клику означало бы копировать сам сайдбар отдельной кнопкой
  // "Назад" без всякой пользы.
  var reportsHistory = [];

  function captureReportsState(view) {
    return {
      view: view,
      periodFrom: document.getElementById('period-from').value,
      periodTo: document.getElementById('period-to').value,
      eqCurrency: document.getElementById('eq-currency').value,
      cmpMode: document.getElementById('structure-cmp-mode').value,
      // Экран проверки импорта — подсостояние вкладки "ИИ" (#/reports/ai/import/<id>).
      aiImport: view === 'ai' && stDetail ? stDetail.id : '',
    };
  }

  function updateReportsBackButton() {
    var btn = document.getElementById('reports-back-btn');
    if (btn) btn.hidden = reportsHistory.length === 0;
  }

  function pushReportsHistory() {
    reportsHistory.push(captureReportsState(reportsView));
    updateReportsBackButton();
  }

  // Интеграция с History API браузера (по прямому запросу — "чтобы
  // отрабатывали назад/вперёд") — ОТДЕЛЬНЫЙ слой поверх reportsHistory
  // выше, не замена ей: reportsHistory/pushReportsHistory по-прежнему
  // считает "Назад" только детализациями (см. её же комментарий), эта же
  // часть пушит запись браузерной истории на КАЖДОЕ переключение вкладки
  // (switchReportsView) — обычные клики по сайдбару тоже должны отменяться
  // кнопкой "Назад" самого браузера, это уже его встроенное ожидание, а не
  // решение конкретно этого приложения.
  //
  // Hash, не путь ("#/reports/over?..."): wallet-web отдаёт статику без
  // серверного роутинга (см. README) — путь вроде "/reports/dyn" при
  // обновлении страницы (F5) ушёл бы прямо на сервер и словил бы 404;
  // hash браузер на сервер никогда не отправляет.
  var isApplyingHistoryState = false; // true — идёт восстановление состояния (popstate/F5/"Назад"), switchReportsView не должен пушить новую запись

  function reportsHashFor(state) {
    var query = 'from=' + encodeURIComponent(state.periodFrom) +
      '&to=' + encodeURIComponent(state.periodTo) +
      '&eq=' + encodeURIComponent(state.eqCurrency) +
      '&cmp=' + encodeURIComponent(state.cmpMode);
    var tail = state.view === 'ai' && state.aiImport ? '/import/' + encodeURIComponent(state.aiImport) : '';
    return '#/reports/' + state.view + tail + '?' + query;
  }

  // Разбор location.hash в то же состояние — используется только при самой
  // первой загрузке страницы (см. boot()), чтобы F5 на "Отчётах" вернул тот
  // же экран/фильтр, а не всегда стартовый "Обзор" с фильтром по умолчанию.
  function parseReportsHash(hash) {
    var m = /^#\/reports\/([a-z]+)(?:\/import\/([0-9a-fA-F-]+))?\?(.*)$/.exec(hash || '');
    if (!m || REPORTS_BUILT_VIEWS.indexOf(m[1]) < 0) return null;
    var params = {};
    m[3].split('&').forEach(function (pair) {
      var kv = pair.split('=');
      if (kv[0]) params[kv[0]] = decodeURIComponent(kv[1] || '');
    });
    if (!params.from || !params.to) return null;
    return {
      screen: 'reports',
      view: m[1],
      periodFrom: params.from,
      periodTo: params.to,
      eqCurrency: params.eq || 'USD',
      cmpMode: params.cmp || 'none',
      aiImport: m[1] === 'ai' && m[2] ? m[2] : '',
    };
  }

  function pushReportsUrlState(view) {
    var state = captureReportsState(view);
    state.screen = 'reports';
    history.pushState(state, '', reportsHashFor(state));
  }

  // Один replaceState (не push — это не новый переход, а уточнение уже
  // показанного экрана) сразу после самой первой отрисовки "Отчётов" (см.
  // boot()): без него history.state первой записи остался бы null, и самое
  // первое нажатие браузерного "Вперёд" после ухода отсюда назад не нашло
  // бы, куда возвращаться (см. popstate-обработчик ниже — он игнорирует
  // записи без state.screen === 'reports').
  function replaceReportsUrlState(view) {
    var state = captureReportsState(view);
    state.screen = 'reports';
    history.replaceState(state, '', reportsHashFor(state));
  }

  // Восстанавливает и фильтр, и вкладку из запомненной записи, а не просто
  // showReportsView() поверх ТЕКУЩЕГО фильтра — иначе кнопка вернула бы на
  // нужную вкладку, но с уже изменённым, чужим фильтром. refreshPeriod() в
  // конце — полная перезагрузка всех вкладок под восстановленный фильтр,
  // тот же вызов, что и у кнопки "Обновить". Общая для трёх источников
  // восстановления — reportsHistory ("Назад"), popstate (браузерные
  // Назад/Вперёд) и самой первой загрузки по hash (F5) — вместо трёх копий
  // одного и того же куска.
  function applyReportsHistoryState(state) {
    document.getElementById('period-from').value = state.periodFrom;
    document.getElementById('period-to').value = state.periodTo;
    document.getElementById('eq-currency').value = state.eqCurrency;
    document.getElementById('structure-cmp-mode').value = state.cmpMode;
    // Пикер валюты не читает #eq-currency сам по себе (это просто hidden
    // input, см. renderReports) — кнопку/список надо перерисовать явно,
    // иначе они молча продолжат показывать валюту, которая была ДО «Назад».
    renderCurrencyPickerButton();
    renderCurrencyPickerList();
    // Восстановление — не новый переход, а возврат к уже существовавшей
    // записи истории: switchReportsView не должен пушить её ещё раз поверх
    // самой себя.
    // Список импортов или экран проверки — до переключения: если статус ИИ
    // ещё не пришёл (F5), refreshAiStatus откроет тот же экран позже.
    if (state.view === 'ai') stShowImport(state.aiImport || null);
    isApplyingHistoryState = true;
    switchReportsView(state.view);
    isApplyingHistoryState = false;
    updateReportsBackButton();
    refreshPeriod();
  }

  function goReportsBack() {
    var state = reportsHistory.pop();
    if (!state) return;
    applyReportsHistoryState(state);
  }

  // Браузерные Назад/Вперёд — попадание на уже существующую запись истории.
  // Если "Отчёты" сейчас даже не открыты (ушли на "Кошельки"/админку) —
  // сперва отстраиваем экран заново (renderReports() сама вызывает
  // switchReportsView('over') внутри — тоже под isApplyingHistoryState,
  // чтобы не запушить лишнюю промежуточную запись), а уже потом накладываем
  // на него реальное состояние из истории.
  window.addEventListener('popstate', function (ev) {
    var state = ev.state;
    if (!state || state.screen !== 'reports') return;
    if (!document.getElementById('reports-shell')) {
      isApplyingHistoryState = true;
      renderReports();
      isApplyingHistoryState = false;
    }
    applyReportsHistoryState(state);
  });

  function reportsNavItemHtml(view, label, enabled) {
    if (!enabled) {
      return (
        '<button type="button" class="nav-item" disabled>' + escapeHtml(label) +
        '<span class="soon">скоро</span></button>'
      );
    }
    return (
      '<button type="button" class="nav-item' + (view === reportsView ? ' active' : '') +
      (isMobileTabView(view) ? ' in-tabbar' : '') +
      '" data-view="' + view + '">' + escapeHtml(label) + '</button>'
    );
  }

  function reportsNavHtml() {
    return REPORTS_NAV.map(function (g) {
      var label = g.group ? '<div class="nav-group-label">' + escapeHtml(g.group) + '</div>' : '';
      var items = g.items.map(function (it) { return reportsNavItemHtml(it[0], it[1], it[2]); }).join('');
      var idAttr = g.id ? ' id="' + g.id + '" hidden' : '';
      return '<div class="nav-group"' + idAttr + '>' + label + items + '</div>';
    }).join('');
  }

  // Переключение вкладки БЕЗ повторного запроса — все четыре (Обзор/Список
  // операций/Структура/Динамика) уже загружены целиком при открытии
  // "Отчётов" (см. refreshPeriod() внизу renderReports()), здесь только
  // видимость и заголовок/активный пункт меню.
  function switchReportsView(view) {
    // "ИИ" скрыт (или статус ещё не пришёл) — прямая ссылка, F5 и
    // "Назад"/"Вперёд" на него открывают "Обзор". Пока статуса нет, просьбу
    // запоминаем: refreshAiStatus переключит, если ИИ окажется включён.
    // То же для «Справки» (refreshDocsStatus).
    if (view === 'ai' && aiStatus !== true) {
      aiRestorePending = aiStatus === null;
      docsRestorePending = false;
      view = 'over';
    } else if (view === 'docs' && docsStatus !== true) {
      docsRestorePending = docsStatus === null;
      aiRestorePending = false;
      view = 'over';
    } else if (view !== 'over') {
      aiRestorePending = false; // пользователь ушёл сам — не перебивать его выбор
      docsRestorePending = false;
    }
    // Ушли со «Справки» — вопрос и ответ не хранятся (спека docs-assistant).
    if (reportsView === 'docs' && view !== 'docs') docsReset();
    // Ушли с "ИИ" посреди разбора — задание снимается, текст остаётся в поле.
    if (reportsView === 'ai' && view !== 'ai' && aiPhase === 'parsing') {
      aiCancelParsing();
      renderAiRoot();
    }
    var enteringAi = view === 'ai' && reportsView !== 'ai';
    // Модальное окно валюты в скрытой вкладке оставило бы страницу инертной
    // (уйти можно "Назад" браузера) — закрываем (currency-form-ux D2).
    if (view !== 'cur') closeCurCurrencyDialog();
    reportsView = view;
    REPORTS_BUILT_VIEWS.forEach(function (v) {
      document.getElementById('view-' + v).hidden = v !== view;
    });
    Array.prototype.forEach.call(document.querySelectorAll('.nav-item[data-view]'), function (btn) {
      btn.classList.toggle('active', btn.getAttribute('data-view') === view);
    });
    Array.prototype.forEach.call(document.querySelectorAll('.mobile-tab[data-tab]'), function (btn) {
      btn.classList.toggle('active', btn.getAttribute('data-tab') === view);
    });
    var moreBtn = document.getElementById('mobile-more-btn');
    if (moreBtn) moreBtn.classList.toggle('active', !isMobileTabView(view));
    // Фильтр периода (сводка + панель) — только на вкладках, которые от него
    // зависят (по прямому запросу: на "Доступе и приглашениях" он был лишним
    // и ломал вид шапки), см. PERIOD_FREE_VIEWS.
    document.querySelector('.reports-header').classList.toggle('no-period', PERIOD_FREE_VIEWS.indexOf(view) >= 0);
    updateOpsSidebarStickyOffset();
    var t = REPORTS_TITLES[view];
    document.getElementById('reports-title').textContent = t[0];
    document.getElementById('reports-subtitle').textContent = t[1];
    // Карта расходов меряет РЕАЛЬНУЮ ширину контейнера (clientWidth) — пока
    // вкладка была скрыта (hidden -> display:none), ширина читалась бы как 0.
    // Пересчитываем именно в момент, когда контейнер становится видимым.
    if (view === 'struct') renderTreemapIfVisible();
    // Импорты: зашли на "ИИ" — список сразу свежий и опрос раз в 5 с, ушли —
    // опрос реже (только ради метки), см. stSchedulePoll.
    if (enteringAi) stLoadImports();
    else stSchedulePoll();
    // Каждое переключение вкладки — запись в браузерной истории (см.
    // isApplyingHistoryState выше), КРОМЕ восстановления уже существующей
    // записи (иначе "Назад" сам себя тут же запушил бы вперёд повторно).
    if (!isApplyingHistoryState) pushReportsUrlState(view);
  }

  // Сворачивание левого меню (по прямому запросу) — состояние переживает
  // перезагрузку страницы (localStorage), это чисто локальное удобство
  // ЭТОГО браузера, не серверные данные, поэтому не через /api. try/catch —
  // приватный режим/заблокированное хранилище не должны ронять сайдбар,
  // просто сворачивание не переживёт следующую загрузку.
  var SIDEBAR_COLLAPSED_KEY = 'reportsSidebarCollapsed';

  function isSidebarCollapsed() {
    try {
      return localStorage.getItem(SIDEBAR_COLLAPSED_KEY) === '1';
    } catch (e) {
      return false;
    }
  }

  function setSidebarCollapsed(collapsed) {
    var shell = document.getElementById('reports-shell');
    if (shell) shell.classList.toggle('sidebar-collapsed', collapsed);
    try {
      localStorage.setItem(SIDEBAR_COLLAPSED_KEY, collapsed ? '1' : '0');
    } catch (e) {
      // приватный режим/заблокированное хранилище — сворачивание отработает
      // в рамках текущей загрузки страницы, просто не запомнится на следующую
    }
    // Карту расходов под новую ширину .reports-main перерисует её
    // ResizeObserver (см. observeTreemapWidth) — отдельно ловить
    // transitionend сайдбара не нужно.
  }

  // Мобильная раскладка "Отчётов" (по прямому запросу — "адаптируй веб под
  // мобильную версию") — та же граница, что и @media (max-width: 720px) в
  // style.css: сайдбар там выдвижной, фильтр периода свёрнут в сводку.
  var MOBILE_LAYOUT_QUERY = '(max-width: 720px)';

  function isMobileLayout() {
    return window.matchMedia(MOBILE_LAYOUT_QUERY).matches;
  }

  function setMobileNavOpen(open) {
    var shell = document.getElementById('reports-shell');
    if (shell) shell.classList.toggle('nav-open', open);
  }

  // Свёрнут ли фильтр периода на десктопе (по прямому запросу — "сделай
  // фильтр сворачиваемым на вебе") — запоминается тем же приёмом, что и
  // свёрнутый сайдбар (isSidebarCollapsed). По умолчанию раскрыт, как и было
  // до сворачивания. На мобильной раскладке не читается и не пишется: там
  // панель всегда стартует свёрнутой и сама закрывается после применения.
  var FILTERS_COLLAPSED_KEY = 'reportsFiltersCollapsed';

  function isPeriodPanelOpenByDefault() {
    if (isMobileLayout()) return false;
    try {
      return localStorage.getItem(FILTERS_COLLAPSED_KEY) !== '1';
    } catch (e) {
      return true;
    }
  }

  function setPeriodPanelOpen(open) {
    var header = document.querySelector('.reports-header');
    if (!header) return;
    header.classList.toggle('filters-open', open);
    document.getElementById('period-summary-btn').setAttribute('aria-expanded', open ? 'true' : 'false');
    updateOpsSidebarStickyOffset(); // высота липкой шапки поменялась
    if (isMobileLayout()) return;
    try {
      localStorage.setItem(FILTERS_COLLAPSED_KEY, open ? '0' : '1');
    } catch (e) {
      // см. setSidebarCollapsed — просто не запомнится на следующую загрузку
    }
  }

  // После "Обновить"/быстрого периода — на мобильной панель закрываем (она
  // перекрывает отчёт), на десктопе оставляем как есть: там её свернули или
  // развернули сознательно.
  function closePeriodPanelOnMobile() {
    if (isMobileLayout()) setPeriodPanelOpen(false);
  }

  // Шапка "Отчётов" на телефоне (по прямому запросу — "фильтр дат занимает
  // много места и так и не прячется"): прокрутка вниз прячет липкую шапку
  // целиком и закрывает раскрытый фильтр, прокрутка вверх возвращает шапку;
  // тап мимо раскрытого фильтра тоже его закрывает. Слушатели — на window/
  // document, поэтому вешаются один раз на загрузку страницы, а не на каждый
  // renderReports() (тот зовут при каждом заходе на "Отчёты").
  var mobileHeaderWired = false;

  function wireMobileHeaderOnce() {
    if (mobileHeaderWired) return;
    mobileHeaderWired = true;
    var lastY = window.scrollY;

    window.addEventListener('scroll', function () {
      var header = document.querySelector('.reports-header');
      var y = window.scrollY;
      if (!header || !isMobileLayout()) { lastY = y; return; }
      if (Math.abs(y - lastY) < 8) return; // дрожание пальца — не повод дёргать шапку
      var hide = y > lastY && y > header.offsetHeight;
      header.classList.toggle('header-hidden', hide);
      if (hide && header.classList.contains('filters-open')) setPeriodPanelOpen(false);
      lastY = y;
    }, { passive: true });

    document.addEventListener('click', function (ev) {
      var header = document.querySelector('.reports-header');
      if (!header || !isMobileLayout() || !header.classList.contains('filters-open')) return;
      if (!header.contains(ev.target)) setPeriodPanelOpen(false);
    });
  }

  // Быстрые периоды мобильной панели фильтра (см. renderReports,
  // #period-presets) — [ключ, подпись]; границы считает periodPresetRange.
  var PERIOD_PRESETS = [
    ['month', 'Этот месяц'],
    ['prev-month', 'Прошлый месяц'],
    ['3m', '3 месяца'],
    ['12m', '12 месяцев'],
    ['year', 'Этот год']
  ];

  // [from, to] в "yyyy-mm-dd" — тот же формат, что у <input type="date">.
  // Конец — сегодня (кроме прошлого месяца), начало — первое число месяца,
  // тот же принцип, что и у дефолтного периода (defaultPeriodFromIso).
  function periodPresetRange(key) {
    var now = new Date();
    var today = isoDate(now);
    var y = now.getFullYear();
    var m = now.getMonth();
    switch (key) {
      case 'prev-month': return [isoDate(new Date(y, m - 1, 1)), isoDate(new Date(y, m, 0))];
      case '3m': return [isoDate(new Date(y, m - 2, 1)), today];
      case '12m': return [isoDate(new Date(y, m - 11, 1)), today];
      case 'year': return [isoDate(new Date(y, 0, 1)), today];
      default: return [isoDate(new Date(y, m, 1)), today];
    }
  }

  // Текст свёрнутой мобильной сводки фильтра + подсветка совпавшего
  // быстрого периода. Зовётся там, где фильтр ПРИМЕНЯЕТСЯ (refreshPeriod,
  // goToOperationsForCategory), а не на каждый 'change' поля: сводка
  // показывает то, по чему построены отчёты, а не недонабранные даты.
  function updatePeriodSummary() {
    var textEl = document.getElementById('period-summary-text');
    if (!textEl) return;
    var fromStr = document.getElementById('period-from').value;
    var toStr = document.getElementById('period-to').value;
    var groupEl = document.getElementById('period-group');
    var groupText = groupEl.options[groupEl.selectedIndex] ? groupEl.options[groupEl.selectedIndex].text.toLowerCase() : '';
    var currency = document.getElementById('eq-currency').value;
    // Две версии: полная — на десктопе, короткая (год двумя цифрами, без
    // группировки) — на телефоне, где сводка стоит в одной строке с заголовком.
    var shortDate = function (iso) { return formatDate(iso).replace(iso.slice(0, 4), iso.slice(2, 4)); };
    textEl.innerHTML =
      '<span class="ps-full">' + escapeHtml(formatDate(fromStr) + ' – ' + formatDate(toStr) + ' · ' + groupText + ' · ' + currency) + '</span>' +
      '<span class="ps-short">' + escapeHtml(shortDate(fromStr) + '–' + shortDate(toStr) + ' · ' + currency) + '</span>';
    Array.prototype.forEach.call(document.querySelectorAll('#period-presets [data-preset]'), function (btn) {
      var range = periodPresetRange(btn.getAttribute('data-preset'));
      btn.classList.toggle('active', range[0] === fromStr && range[1] === toStr);
    });
  }

  // Стартовый экран после Google-логина (см. boot() — раньше здесь была
  // renderDashboard(), demo-CRUD "Кошельков"; убрана целиком, 2026-09-11,
  // см. её историю в git — кнопка "Настройки" ведёт на renderSettings()).
  // Читает currentUser МОДУЛЬНОЙ переменной (не параметром) — тем же
  // приёмом, что и "Назад" у renderAdmin(): к моменту вызова она уже
  // выставлена (только в boot(), из GET /auth/me).
  //
  // Баннер режима "Посмотреть как клиент" — показывается ТОЛЬКО пока
  // viewAsUser выставлен (см. её объявление и wireAdminViewAs). Пустая
  // строка вне этого режима — обычный вход на "Отчёты" не показывает
  // ничего лишнего в шапке, ни одна другая функция экрана не завязана на
  // присутствие/отсутствие баннера.
  function viewAsBannerHtml() {
    if (!viewAsUser) return '';
    return (
      '<div class="view-as-banner">' +
      'Вы просматриваете как <strong>' + escapeHtml(viewAsUser.email) + '</strong> — только чтение' +
      '<button type="button" class="btn btn-secondary" id="view-as-exit-btn">Завершить просмотр</button>' +
      '</div>'
    );
  }

  // Полноэкранный сайдбар-кабинет (servers/Design/.../Отчёты - веб.dc.html),
  // а не карточка по центру, как остальные экраны — body.reports-open (см.
  // style.css) переключает раскладку body/#app, setWide() её снимает у
  // любого другого экрана верхнего уровня.
  function renderReports() {
    document.body.classList.add('reports-open');
    reportsView = 'over';
    reportsHistory = []; // новый заход на "Отчёты" — прежняя история (если была) относится к уже снесённому DOM
    // Кэш ответов (см. fetchReport) — туда же: пока пользователь был на
    // "Кошельках", он мог добавить операцию/кошелёк, и старые числа этого
    // же периода больше не актуальны. "Назад" ВНУТРИ одного открытого
    // "Отчётов" по-прежнему восстанавливает без похода в сеть — сбрасывается
    // только САМ вход на "Отчёты", не каждый переход между их вкладками.
    reportsCache = {};
    // Снимок "Доступа и приглашений" (см. ниже) — та же логика, что и у
    // reportsCache выше: новый заход на "Отчёты" не должен показать состав
    // участников или только что созданную ссылку от ПРЕДЫДУЩЕГО захода.
    accessSnapshot = null;
    accessJustCreated = null;
    accessCopiedId = null;
    curCurrencyForm = null; // форма валюты прошлого захода (мог смениться и режим "Посмотреть как клиент") не переживает ухода
    curCurrencyIconPickerOpen = false;
    curIconQuery = '';
    curCurrenciesError = '';
    resetAi(); // незавершённый разбор прошлого захода снимается, карточка не переживает ухода
    // Сохранённое состояние — сразу в разметке, а не toggle-ом после вставки:
    // иначе при каждом заходе на "Отчёты" было бы видно, как свёрнутый
    // сайдбар на мгновение разворачивается и тут же сворачивается обратно
    // (CSS-transition играет на КАЖДОЕ изменение класса, а не только на
    // клик пользователя, см. setSidebarCollapsed).
    var collapsedClass = isSidebarCollapsed() ? ' sidebar-collapsed' : '';

    app.innerHTML =
      '<div class="reports-shell' + collapsedClass + '" id="reports-shell">' +
      '<aside class="reports-sidebar">' +
      '<div class="brand"><div class="brand-kicker">Кошельки</div><div class="brand-title">Отчёты</div></div>' +
      '<nav class="reports-nav">' + reportsNavHtml() + '</nav>' +
      '<div class="sidebar-footer">' +
      '<div class="user-card">' + avatarHtml(currentUser) +
      '<div class="user-info">' +
      '<div class="user-name">' + escapeHtml(currentUser.name) + '</div>' +
      roleBadgeHtml(currentUser.role) +
      '</div></div>' +
      '<button type="button" class="btn btn-secondary" id="settings-link-btn">Настройки</button>' +
      adminLinkButtonHtml(currentUser) +
      '<button type="button" class="btn btn-secondary" id="logout-btn">Выйти</button>' +
      '</div>' +
      '</aside>' +
      '<main class="reports-main">' +
      '<header class="reports-header' + (isPeriodPanelOpenByDefault() ? ' filters-open' : '') + '">' +
      viewAsBannerHtml() +
      '<div class="reports-header-top">' +
      '<button type="button" class="sidebar-toggle-btn" id="sidebar-toggle-btn" ' +
      'title="Свернуть/показать меню" aria-label="Свернуть/показать меню">☰</button>' +
      '<button type="button" class="reports-back-btn" id="reports-back-btn" hidden>← Назад</button>' +
      '<h1 id="reports-title"></h1>' +
      '</div>' +
      '<div class="reports-subtitle" id="reports-subtitle"></div>' +
      // Сводка фильтра (по прямому запросу — "фильтры дат на мобильной
      // плохи", потом "сделай фильтр сворачиваемым на вебе"): кнопка-строка
      // ("01.09.2026 – 10.10.2026 · по месяцам · USD"), по клику
      // сворачивает/раскрывает .reports-controls (см. setPeriodPanelOpen,
      // isPeriodPanelOpenByDefault). На узком экране контролы занимали
      // полэкрана липкой шапки — там панель стартует свёрнутой.
      '<button type="button" class="period-summary-btn" id="period-summary-btn" ' +
      'aria-expanded="' + (isPeriodPanelOpenByDefault() ? 'true' : 'false') + '" ' +
      'aria-controls="reports-controls">' +
      '<span class="period-summary-text" id="period-summary-text"></span>' +
      '<svg class="currency-picker-arrow" viewBox="0 0 10 6" width="10" height="6" aria-hidden="true">' +
      '<path d="M1 1l4 4 4-4" fill="none" stroke="currentColor" stroke-width="1.5" ' +
      'stroke-linecap="round" stroke-linejoin="round"/></svg>' +
      '</button>' +
      '<div class="reports-controls" id="reports-controls" style="margin-top:14px">' +
      // Быстрые периоды (см. PERIOD_PRESETS) — два date-пикера подряд
      // самый медленный способ выбрать "прошлый месяц", особенно на телефоне.
      '<div class="period-presets" id="period-presets">' +
      PERIOD_PRESETS.map(function (p) {
        return '<button type="button" class="ops-chip" data-preset="' + p[0] + '">' + escapeHtml(p[1]) + '</button>';
      }).join('') +
      '</div>' +
      // Пикер валюты — по прямому запросу ("флаг страны" в списке): обычный
      // <select> не умеет показывать иконку внутри <option> ни в одном
      // браузере, поэтому вместо него — кнопка + свой выпадающий список
      // (div'ы, не <option>), с флагом-иконкой у каждой строки. #eq-currency
      // — hidden input, единственный источник истины для остального кода
      // (eqCurrencyValue/captureReportsState/goReportsBack — ни один не
      // изменился, они как читали/писали #eq-currency.value, так и читают/
      // пишут, вне зависимости от того, что теперь стоит за этим id).
      // Список — заполняется loadCurrencies() из GET /api/reports/currencies
      // (справочник); стартовое значение — сохранённое в "Настройках"
      // предпочтение (localStorage, см. getEqCurrencyPreference), либо
      // "USD" по умолчанию — с ним "Отчёты" открываются сразу, не дожидаясь
      // ответа сети.
      '<label class="currency-picker" id="currency-picker">Валюта эквивалента' +
      '<button type="button" class="currency-picker-btn" id="currency-picker-btn">' +
      '<span class="currency-picker-display" id="currency-picker-display"><span class="currency-picker-flag"></span><span>' +
      escapeHtml(getEqCurrencyPreference() || 'USD') + '</span></span>' +
      '<svg class="currency-picker-arrow" viewBox="0 0 10 6" width="10" height="6" aria-hidden="true">' +
      '<path d="M1 1l4 4 4-4" fill="none" stroke="currentColor" stroke-width="1.5" ' +
      'stroke-linecap="round" stroke-linejoin="round"/></svg>' +
      '</button>' +
      '<input type="hidden" id="eq-currency" value="' + escapeHtml(getEqCurrencyPreference() || 'USD') + '">' +
      '<div class="currency-picker-list" id="currency-picker-list" hidden></div>' +
      '</label>' +
      '<label>С<input type="date" id="period-from" value="' + (periodPreferenceFrom() || defaultPeriodFromIso()) + '"></label>' +
      '<label>По<input type="date" id="period-to" value="' + (periodPreferenceTo() || defaultPeriodToIso()) + '"></label>' +
      // Период группировки графиков (по прямому запросу, 2026-09-11) — один
      // на все три графика, что раньше молча жили каждый на своём
      // фиксированном окне (12/24 месяца), не на выбранном периоде: "Обзор"
      // (renderOverviewMonthlyChart), "Динамика" (renderDynamicsChart) и
      // "Категории во времени" (renderCatsChart) теперь строятся по
      // одинаковым бакетам (см. buildBuckets/groupByValue ниже), длина
      // которых — это самое поле, а окно — сам period-from/-to, а не
      // отдельная "витрина".
      '<label>Группировка<select id="period-group">' +
      ['day', 'week', 'month', 'year'].map(function (v) {
        var titles = { day: 'По дням', week: 'По неделям', month: 'По месяцам', year: 'По годам' };
        return '<option value="' + v + '"' + (v === (periodPreferenceGroupBy() || 'month') ? ' selected' : '') + '>' +
          titles[v] + '</option>';
      }).join('') +
      '</select></label>' +
      '<button type="button" class="btn" id="period-refresh-btn">Обновить</button>' +
      '</div>' +
      '</header>' +
      '<div class="reports-body">' +
      '<div id="view-over">' +
      '<div class="kpi-grid" id="overview-kpis"><p class="sub">Загрузка…</p></div>' +
      // График "Расход и доход" — на всю ширину страницы, не в
      // overview-grid-2 (два столбца по половине): раньше он всегда был "по
      // месяцу" (12 узких столбцов, в половину ширины помещался легко) — с
      // группировкой по дням/неделям на широком периоде столбцов может быть
      // сотни, в половине экрана они превращались в нечитаемую кашу (по
      // прямому запросу — "график теперь может быть большим — широким,
      // мешается").
      '<section class="report-section">' +
      '<div class="section-head"><h2 id="overview-monthly-title">Расход и доход</h2>' +
      '<button type="button" class="link-btn" id="overview-dyn-link">Вся динамика →</button></div>' +
      '<div id="overview-monthly-chart"><p class="sub">Загрузка…</p></div>' +
      '</section>' +
      '<div class="overview-grid-2">' +
      '<section class="report-section">' +
      '<div class="section-head"><h2>Структура</h2>' +
      '<button type="button" class="link-btn" id="overview-struct-link">Подробно →</button></div>' +
      '<div id="overview-mini-structure"><p class="sub">Загрузка…</p></div>' +
      '</section>' +
      '<section class="report-section">' +
      '<h2>По дням недели</h2>' +
      '<div id="overview-weekday-chart"><p class="sub">Загрузка…</p></div>' +
      '</section>' +
      '</div>' +
      // "Что изменилось" — по прямому запросу (2026-09-12) снова внизу
      // "Обзора": ей в принципе нечего показывать без периода сравнения
      // (см. ветку !cmpRange ниже), так что наверху страницы она чаще всего
      // просто просила выбрать сравнение — вниз, под то, что уже видно сразу.
      '<section class="report-section">' +
      '<div class="section-head"><h2>Что изменилось сильнее всего</h2>' +
      '<label class="section-head-select">Сравнить с<select id="structure-cmp-mode">' +
      '<option value="none">Без сравнения</option>' +
      '<option value="prev">Предыдущим периодом</option>' +
      '<option value="year">Тем же периодом год назад</option>' +
      '</select></label></div>' +
      '<div id="overview-moves"><p class="sub">Загрузка…</p></div>' +
      '</section>' +
      '</div>' +
      '<div id="view-ops" hidden>' +
      '<div class="ops-grid">' +
      '<div class="ops-main">' +
      '<section class="report-section ops-toolbar">' +
      '<div class="ops-search-row">' +
      '<input type="text" id="ops-search" placeholder="Место, статья, кошелёк">' +
      '</div>' +
      '<div id="ops-filters"></div>' +
      '</section>' +
      '<section class="report-section"><div id="ops-list"><p class="sub">Загрузка…</p></div></section>' +
      '</div>' +
      '<div class="ops-sidebar" id="ops-sidebar"></div>' +
      '</div>' +
      '</div>' +
      '<div id="view-struct" hidden>' +
      '<div class="structure-grid">' +
      '<section class="report-section">' +
      '<h2>Карта расходов</h2>' +
      '<div class="treemap-container" id="structure-treemap"><p class="sub">Загрузка…</p></div>' +
      '<div class="treemap-note" id="structure-treemap-note"></div>' +
      '</section>' +
      '<section class="report-section">' +
      '<h2>Категории</h2>' +
      '<div id="structure-result"><p class="sub">Загрузка…</p></div>' +
      '</section>' +
      '</div>' +
      '</div>' +
      '<div id="view-dyn" hidden>' +
      '<section class="report-section">' +
      '<h2 id="dyn-chart-title">Расход и доход</h2>' +
      '<div id="dyn-chart"><p class="sub">Загрузка…</p></div>' +
      '</section>' +
      '<div class="overview-grid-2">' +
      '<section class="report-section" id="dyn-selected"><p class="sub">Загрузка…</p></section>' +
      '<section class="report-section">' +
      '<h2>Год к году</h2>' +
      '<div id="dyn-years"><p class="sub">Загрузка…</p></div>' +
      '</section>' +
      '</div>' +
      '</div>' +
      '<div id="view-cats" hidden>' +
      '<section class="report-section">' +
      '<div id="cats-chart"><p class="sub">Загрузка…</p></div>' +
      '</section>' +
      '<section class="report-section">' +
      '<h2>Категории</h2>' +
      '<div class="wallet-search-row"><input type="text" id="cats-search" placeholder="Найти категорию"></div>' +
      '<div class="cats-cards-grid" id="cats-cards"><p class="sub">Загрузка…</p></div>' +
      '</section>' +
      '</div>' +
      '<div id="view-wal" hidden>' +
      '<div class="kpi-grid" id="wallet-kpis"><p class="sub">Загрузка…</p></div>' +
      '<section class="report-section">' +
      '<div class="wallet-search-row">' +
      '<input type="text" id="wallet-search" placeholder="Кошелёк, тип или валюта (например EUR)">' +
      '</div>' +
      '<div class="wallet-table-head" id="wallet-table-head">' +
      '<span></span>' +
      '<span class="wallet-sort-th" data-sort-key="name">Кошелёк<span class="wallet-sort-arrow"></span></span>' +
      '<span>12 месяцев</span>' +
      '<span class="wallet-sort-th" data-sort-key="startEqNum">На начало<span class="wallet-sort-arrow"></span></span>' +
      '<span class="wallet-sort-th" data-sort-key="inEqNum">Пришло<span class="wallet-sort-arrow"></span></span>' +
      '<span class="wallet-sort-th" data-sort-key="outEqNum">Ушло<span class="wallet-sort-arrow"></span></span>' +
      '<span class="wallet-sort-th" data-sort-key="endEqNum">На конец<span class="wallet-sort-arrow"></span></span>' +
      '</div>' +
      '<div id="wallet-table"><p class="sub">Загрузка…</p></div>' +
      '</section>' +
      '<section class="report-section" id="wallet-currencies-section" hidden>' +
      '<h2>Состояние по валюте</h2>' +
      '<div class="wallet-currencies-grid" id="wallet-currencies"></div>' +
      '</section>' +
      '</div>' +
      '<div id="view-cap" hidden>' +
      '<div class="kpi-grid" id="capital-kpis"><p class="sub">Загрузка…</p></div>' +
      '<section class="report-section"><div id="capital-table"></div></section>' +
      '</div>' +
      '<div id="view-cur" hidden>' +
      '<div id="cur-root"><p class="sub">Загрузка…</p></div>' +
      // Вне #cur-root (currency-form-ux D2): renderCurList его не пересоздаёт.
      '<dialog id="cur-currency-dialog" class="cur-dialog" aria-label="Валюта"></dialog>' +
      '</div>' +
      '<div id="view-acc" hidden>' +
      '<div id="access-root"><p class="sub">Загрузка…</p></div>' +
      // Вне #access-root: тот перерисовывается целиком на каждое действие
      // (копирование ссылки, смена роли в форме) и затёр бы QR и опрос.
      // Для всех, не только владельца: бот подключается к СВОЕМУ аккаунту.
      '<section class="access-card access-telegram-card">' +
      '<h2>Telegram-бот</h2>' +
      '<p class="sub" style="margin:4px 0 14px">Писать траты сообщением и спрашивать про кошельки. ' +
      'Бот видит отчёты и может только добавлять траты — править и удалять операции он не умеет. ' +
      'Отключить его можно здесь в любой момент.</p>' +
      '<div id="telegram-root"><p class="sub">Загрузка…</p></div>' +
      '</section>' +
      '</div>' +
      '<div id="view-icons" hidden>' +
      '<div id="icons-root"><p class="sub">Загрузка…</p></div>' +
      '</div>' +
      '<div id="view-ai" hidden>' +
      '<div id="ai-root"></div>' +
      '<div id="st-root"></div>' +
      '</div>' +
      '<div id="view-docs" hidden>' +
      '<div id="docs-root"></div>' +
      '</div>' +
      '</div>' +
      '</main>' +
      mobileTabbarHtml() +
      // Затемнение под шторкой "Ещё" — только на мобильной раскладке
      // (style.css), тап по нему закрывает шторку.
      '<div class="reports-backdrop" id="reports-backdrop"></div>' +
      '</div>';

    switchReportsView(reportsView); // проставляет заголовок/активный пункт — саму разметку уже вставили выше
    wireAvatarFallback(currentUser);
    // На мобильной раскладке ☰ не сворачивает сайдбар (его там и так нет в
    // потоке), а выдвигает его поверх контента — и это состояние НЕ
    // запоминается: открытое меню после перезагрузки на телефоне только мешало бы.
    document.getElementById('sidebar-toggle-btn').addEventListener('click', function () {
      if (isMobileLayout()) setMobileNavOpen(!document.getElementById('reports-shell').classList.contains('nav-open'));
      else setSidebarCollapsed(!isSidebarCollapsed());
    });
    document.getElementById('reports-backdrop').addEventListener('click', function () { setMobileNavOpen(false); });
    document.getElementById('period-summary-btn').addEventListener('click', function () {
      setPeriodPanelOpen(!document.querySelector('.reports-header').classList.contains('filters-open'));
    });
    Array.prototype.forEach.call(document.querySelectorAll('#period-presets [data-preset]'), function (btn) {
      btn.addEventListener('click', function () {
        var range = periodPresetRange(btn.getAttribute('data-preset'));
        document.getElementById('period-from').value = range[0];
        document.getElementById('period-to').value = range[1];
        persistPeriodPreference();
        closePeriodPanelOnMobile();
        refreshPeriod();
      });
    });

    document.getElementById('settings-link-btn').addEventListener('click', renderSettings);
    document.getElementById('logout-btn').addEventListener('click', function () {
      fetch('/auth/logout', { method: 'POST', credentials: 'include' }).then(function () {
        viewAsUser = null; // не переживает выход — следующий вход (даже другим человеком) не должен унаследовать чужой режим просмотра
        chatForget(); // лента чата тоже (add-web-chat)
        renderLogin();
      });
    });
    if (currentUser.role === 'admin') {
      document.getElementById('admin-link-btn').addEventListener('click', renderAdmin);
    }
    // Кнопка баннера viewAsBannerHtml() — есть в разметке, только когда
    // viewAsUser выставлен (см. её текст выше), поэтому getElementById
    // безопасно вернёт null в обычном режиме, addEventListener на null не
    // навешивается.
    var viewAsExitBtn = document.getElementById('view-as-exit-btn');
    if (viewAsExitBtn) {
      viewAsExitBtn.addEventListener('click', function () {
        viewAsUser = null;
        renderAdmin(); // назад к таблице пользователей, откуда и зашли
      });
    }
    Array.prototype.forEach.call(document.querySelectorAll('.nav-item[data-view]'), function (btn) {
      btn.addEventListener('click', function () {
        switchReportsView(btn.getAttribute('data-view'));
        setMobileNavOpen(false); // выбрали пункт — выдвижное меню больше не нужно (на десктопе no-op)
      });
    });
    Array.prototype.forEach.call(document.querySelectorAll('.mobile-tab[data-tab]'), function (btn) {
      btn.addEventListener('click', function () {
        switchReportsView(btn.getAttribute('data-tab'));
        setMobileNavOpen(false);
        window.scrollTo(0, 0);
      });
    });
    document.getElementById('mobile-more-btn').addEventListener('click', function () {
      setMobileNavOpen(!document.getElementById('reports-shell').classList.contains('nav-open'));
    });
    wireMobileHeaderOnce();

    wireOpsEvents();
    wireOpsInfiniteScroll();
    wireCatsEvents();
    wireWalletEvents();
    wireCapitalEvents();
    wireCurEvents();
    wireAccessEvents();

    // Персист дат при РУЧНОМ выборе в самих полях (см. setPeriodPreference
    // выше) — 'change', не 'input': тот же момент, когда пользователь
    // закрыл date-picker/закончил ввод, что и у нативного поведения поля.
    // Программные изменения .value (drill-down по графику в конкретный
    // месяц, captureReportsState/goReportsBack — "Назад" на прежний фильтр)
    // событие 'change' не диспатчат, поэтому естественно не перетирают этим
    // сохранённый ручной выбор.
    function persistPeriodPreference() {
      setPeriodPreference(
        document.getElementById('period-from').value,
        document.getElementById('period-to').value,
        groupByValue()
      );
    }
    document.getElementById('period-from').addEventListener('change', persistPeriodPreference);
    document.getElementById('period-to').addEventListener('change', persistPeriodPreference);
    // Группировка графиков — тоже персист + сразу refreshPeriod() (не только
    // при "Обновить"): смена этого поля меняет форму ВСЕХ трёх графиков
    // (Обзор/Динамика/Категории), ждать отдельного клика незачем, тот же
    // приём, что и у structure-cmp-mode ниже.
    document.getElementById('period-group').addEventListener('change', function () {
      persistPeriodPreference();
      refreshPeriod();
    });

    // "Обновить" — ЕДИНСТВЕННОЕ место, где кэш (см. fetchReport) намеренно
    // сбрасывается целиком перед новым refreshPeriod(): по прямому запросу,
    // "перезапрос только по кнопке обновить". Смена самого фильтра
    // (period-from/to, eq-currency, cmp-mode) кэш не трогает — ей и не
    // нужно, другие значения полей сами дают другой ключ кэша (см. cacheKey
    // в fetchReport), первый запрос под них в любом случае уйдёт в сеть.
    // Справочник валют перечитывается тут же (wallet-web#12): «Обновить»
    // пользователь понимает как «всё заново», а флаг «В эквиваленте»,
    // снятый на телефоне, иначе дошёл бы до пикеров только при новом входе
    // в «Отчёты». Порядок — как при входе: loadCurrencies(), затем
    // refreshPeriod().
    document.getElementById('period-refresh-btn').addEventListener('click', function () {
      reportsCache = {};
      closePeriodPanelOnMobile();
      loadCurrencies();
      refreshPeriod();
    });
    // Смена режима сравнения — тоже полный refreshPeriod() (он сам зовёт
    // refreshStructure() в конце): KPI-чипы и "Что изменилось" на "Обзоре"
    // зависят от cmp-периода не меньше, чем "Структура" — раньше, когда
    // cmp-mode влиял только на "Структуру", здесь звался один refreshStructure(),
    // но теперь пересчитывать нужно оба экрана разом. Кэш здесь НЕ сбрасывается
    // (в отличие от "Обновить" выше) — новый cmp_from/cmp_to и так не совпадёт
    // с уже закэшированным ключом, а всё, что от cmp-режима не зависит
    // (график по месяцам, "Список операций", "Категории"...), заново
    // перезапрашивать незачем.
    document.getElementById('structure-cmp-mode').addEventListener('change', refreshPeriod);

    document.getElementById('overview-struct-link').addEventListener('click', function () {
      pushReportsHistory();
      switchReportsView('struct');
    });
    document.getElementById('overview-dyn-link').addEventListener('click', function () {
      pushReportsHistory();
      switchReportsView('dyn');
    });
    document.getElementById('reports-back-btn').addEventListener('click', goReportsBack);

    wireCurrencyPicker();
    loadCurrencies();
    refreshPeriod();
    // Вне refreshPeriod() специально — ни "Курсы валют", ни "Доступ и
    // приглашения" не зависят от периода/валюты эквивалента, пересчитывать
    // их на каждую смену дат или клик "Обновить" незачем.
    refreshCurrencyPairs();
    refreshAccess();
    telegramJustLinked = false; // «Готово — подключён» — только сразу после подключения
    refreshTelegram();
    refreshIcons();
    renderAiRoot();
    refreshAiStatus();
    // Новое открытие «Отчётов» — новый экран «Справки»: прежний вопрос и
    // ответ (и запрос в полёте) не переживают закрытие.
    docsReset();
    refreshDocsStatus();
    updateOpsSidebarStickyOffset();
    wireOpsSidebarStickyResize();
  }

  // Сайдбар "Списка операций" липнет под шапкой при прокрутке (по прямому
  // запросу — "если прокручиваем вниз, оно должно быть видно"), а не
  // прокручивается вместе со страницей и не пропадает за верхним краем.
  // Высота .reports-header — НЕ константа (перенос .reports-controls на
  // узком экране её меняет), чистым CSS без замера не подогнать — отсюда
  // JS, который выставляет её как CSS-переменную --reports-header-h, а
  // .ops-sidebar (см. style.css) уже сам строит top/max-height через
  // calc(). max-height + overflow-y: auto там же — тот самый оговорённый
  // случай "сайдбар глубже окна": тогда он не перекрывает соседей, а
  // прокручивается внутри своих границ, не вместе со страницей.
  function updateOpsSidebarStickyOffset() {
    var headerEl = document.querySelector('.reports-header');
    if (!headerEl) return; // "Отчёты" сейчас не показаны (ушли на "Кошельки"/админку)
    document.documentElement.style.setProperty('--reports-header-h', headerEl.offsetHeight + 'px');
  }

  // Один слушатель на всю жизнь SPA (тот же приём, что и
  // wireCurrencyPickerOutsideClick) — resize не привязан к конкретному
  // заходу на "Отчёты", а сама функция выше безопасно no-op, если их сейчас
  // нет на экране.
  var opsSidebarStickyResizeWired = false;
  function wireOpsSidebarStickyResize() {
    if (opsSidebarStickyResizeWired) return;
    opsSidebarStickyResizeWired = true;
    window.addEventListener('resize', updateOpsSidebarStickyOffset);
  }

  // Ровно один accept-запрос на загрузку страницы (не на каждый заход в
  // "Отчёты") — token уже потреблён сервером после первого успеха (см.
  // wallet-api openapi.yaml, POST /api/invites/accept, "одноразово"), а
  // clearPendingInviteToken() убирает его из localStorage сразу после ЛЮБОГО
  // исхода (включая 409/410) — исход, даже неудачный, окончателен, повторный
  // показ той же ошибки при следующей загрузке не добавил бы ничего нового.
  function acceptPendingInviteIfAny() {
    var token = getPendingInviteToken();
    if (!token) return Promise.resolve();

    function accept(replaceEmptyLedger) {
      return apiJson('/api/invites/accept', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: token, replace_empty_ledger: replaceEmptyLedger }),
      });
    }

    function acceptedAlert(result) {
      if (result) window.alert('Приглашение принято — теперь у вас есть доступ к этому кошельку.');
    }

    return accept(false)
      .then(function (result) {
        clearPendingInviteToken();
        acceptedAlert(result);
      })
      .catch(function (err) {
        // Свой кошелёк пуст (ни одной записи, других участников нет) —
        // заменить его приглашённым можно без потерь, но только с явного
        // согласия: сервер удалит пустой кошелёк и примет приглашение одной
        // транзакцией (wallet-api README, "Доступ и приглашения").
        if (err.status === 409 && err.body && err.body.ledger_empty) {
          var replace = window.confirm(
            'У вас уже есть свой кошелёк, но он пуст. Удалить его и присоединиться ' +
              'к кошельку, в который вас пригласили?'
          );
          if (replace) {
            return accept(true)
              .then(function (result) {
                clearPendingInviteToken();
                acceptedAlert(result);
              })
              .catch(function (retryErr) {
                clearPendingInviteToken();
                reportAcceptError(retryErr);
              });
          }
        }
        clearPendingInviteToken();
        reportAcceptError(err);
      });

    function reportAcceptError(err) {
      // 409 — самая частая и самая непрозрачная причина ("почему я не вижу
      // операций владельца?"): у принимающего уже есть свой кошелёк, и
      // приглашение НЕ применилось (см. invites_repo::accept_invite,
      // AcceptStatus::kAlreadyHasLedger — ссылка при этом остаётся рабочей
      // для кого-то другого). Сюда попадаем, если кошелёк не пуст или
      // пользователь отказался заменить пустой.
      if (err.status === 409) {
        var why = err.body && err.body.ledger_empty
          ? 'у вас уже есть свой кошелёк'
          : 'у вас уже есть свой кошелёк с записями — заменить его приглашённым нельзя';
        window.alert(
          'Приглашение не применено: ' + why + ', поэтому вы продолжите видеть ' +
            'только свои операции, а не операции владельца приглашения. Ссылка ещё ' +
            'действительна и её можно передать тому, у кого своего кошелька нет.'
        );
        return;
      }
      if (err.status === 410) {
        window.alert(
          'Не удалось принять приглашение: ссылка больше не действует ' +
            '(уже использована, отозвана или истёк срок действия). Попросите ' +
            'владельца прислать новую.'
        );
        return;
      }
      window.alert('Не удалось принять приглашение: ' + err.message);
    }
  }

  // ===== Бейдж версии (openspec/changes/service-versions) =====
  // «web <build>» в правом нижнем углу всех экранов. Кнопка живёт вне #app
  // (index.html), поэтому перерисовки экранов через app.innerHTML её не
  // трогают. Версия веба — публичный /version.json (nginx, тот же файл, что
  // /version), один раз при загрузке; нет ответа — бейджа нет. Подсказка:
  // у admin — сводка GET /api/versions гейтвея, новый запрос на каждое
  // открытие; у остальных и на экране входа — одна строка веба. Роль — из
  // currentUser в момент открытия, так что вход/выход ничего не переподписывают.
  var versionBadge = document.getElementById('version-badge');
  var webVersion = null; // ответ /version.json
  var versionTip = null; // открытая подсказка (div в body) или null
  // Номер открытия: ответ /api/versions, пришедший после закрытия или к
  // предыдущему открытию, отбрасывается.
  var versionTipSeq = 0;
  // Открыта тапом/кликом — не закрывается уходом курсора, только Esc,
  // кликом вне, повторным тапом или потерей фокуса.
  var versionTipPinned = false;
  var versionTipHovered = false;

  function versionStartedAt(iso) {
    var d = iso ? new Date(iso) : null;
    if (!d || isNaN(d.getTime())) return '—';
    function p(n) { return (n < 10 ? '0' : '') + n; }
    return p(d.getDate()) + '.' + p(d.getMonth() + 1) + ' ' + p(d.getHours()) + ':' + p(d.getMinutes());
  }

  function versionRowHtml(s) {
    var name = '<td>' + escapeHtml(s.service || '—') + '</td>';
    if (s.error) return '<tr>' + name + '<td colspan="3" class="vt-err">нет ответа</td></tr>';
    return (
      '<tr>' + name +
      '<td>' + escapeHtml(s.build || '—') + '</td>' +
      '<td class="vt-mono">' + escapeHtml(s.git_commit ? String(s.git_commit).slice(0, 7) : '—') + '</td>' +
      '<td>' + escapeHtml(versionStartedAt(s.started_at)) + '</td></tr>'
    );
  }

  function versionTipHtml(title, rows, note) {
    return (
      '<div class="vt-title">' + escapeHtml(title) + '</div>' +
      (rows.length
        ? '<table><thead><tr><th>Сервис</th><th>Сборка</th><th>Коммит</th><th>Запущен</th></tr></thead><tbody>' +
          rows.map(versionRowHtml).join('') + '</tbody></table>'
        : '') +
      (note ? '<div class="vt-note">' + escapeHtml(note) + '</div>' : '')
    );
  }

  // Над бейджем, вплотную (без зазора — иначе курсор по пути к подсказке
  // «уходил» бы с обоих и она закрывалась), правым краем по бейджу.
  function placeVersionTip() {
    var r = versionBadge.getBoundingClientRect();
    versionTip.style.right = Math.max(8, window.innerWidth - r.right) + 'px';
    versionTip.style.bottom = window.innerHeight - r.top + 'px';
  }

  function openVersionTip() {
    if (versionTip || !webVersion) return;
    var seq = ++versionTipSeq;
    versionTip = document.createElement('div');
    versionTip.className = 'version-tip';
    versionTip.id = 'version-tip';
    versionTip.setAttribute('role', 'tooltip');
    versionTip.addEventListener('pointerenter', function () { versionTipHovered = true; });
    versionTip.addEventListener('pointerleave', function (e) {
      versionTipHovered = false;
      if (e.pointerType === 'mouse' && !versionTipPinned && !versionBadge.contains(e.relatedTarget)) {
        closeVersionTip();
      }
    });
    versionBadge.setAttribute('aria-expanded', 'true');
    versionBadge.setAttribute('aria-describedby', 'version-tip');
    document.body.appendChild(versionTip);

    if (!(currentUser && currentUser.role === 'admin')) {
      versionTip.innerHTML = versionTipHtml('Версия', [webVersion]);
      placeVersionTip();
      return;
    }
    versionTip.innerHTML = versionTipHtml('Версии сервисов', [], 'Загрузка…');
    placeVersionTip();
    apiFetch('/api/versions', { credentials: 'include' })
      .then(function (res) {
        if (!res.ok) throw new Error('HTTP ' + res.status);
        return res.json();
      })
      .then(function (data) {
        if (seq !== versionTipSeq || !versionTip) return;
        versionTip.innerHTML = versionTipHtml('Версии сервисов', (data && data.services) || []);
        placeVersionTip();
      })
      .catch(function () {
        if (seq !== versionTipSeq || !versionTip) return;
        versionTip.innerHTML = versionTipHtml('Версии сервисов', [webVersion], 'Сводка версий недоступна');
        placeVersionTip();
      });
  }

  function closeVersionTip() {
    if (!versionTip) return;
    versionTipSeq++;
    versionTip.parentNode.removeChild(versionTip);
    versionTip = null;
    versionTipPinned = false;
    versionTipHovered = false;
    versionBadge.setAttribute('aria-expanded', 'false');
    versionBadge.removeAttribute('aria-describedby');
  }

  function initVersionBadge() {
    if (!versionBadge) return;
    // Мышь: наведение открывает, уход с бейджа и подсказки — закрывает.
    versionBadge.addEventListener('pointerenter', function (e) {
      if (e.pointerType === 'mouse') openVersionTip();
    });
    versionBadge.addEventListener('pointerleave', function (e) {
      if (e.pointerType !== 'mouse' || versionTipPinned) return;
      if (versionTip && versionTip.contains(e.relatedTarget)) return;
      closeVersionTip();
    });
    // Тап/клик закрепляет открытую подсказку, повторный — закрывает.
    // Фокус (Tab, а на телефоне — тот же тап) открывает раньше click,
    // поэтому «открыта, но не закреплена» здесь — значит, закрепить.
    versionBadge.addEventListener('click', function () {
      if (versionTip && versionTipPinned) {
        closeVersionTip();
        return;
      }
      openVersionTip();
      versionTipPinned = true;
    });
    versionBadge.addEventListener('focus', openVersionTip);
    versionBadge.addEventListener('blur', function () {
      if (!versionTipHovered) closeVersionTip();
    });
    document.addEventListener('keydown', function (e) {
      if (versionTip && (e.key === 'Escape' || e.key === 'Esc')) closeVersionTip();
    });
    // Клик/тап вне — закрыть, но сам клик не гасить: он дойдёт до того, во
    // что попал (capture — чтобы закрыться раньше, чем обработчик цели
    // перерисует экран).
    document.addEventListener(
      'click',
      function (e) {
        if (versionTip && !versionTip.contains(e.target) && !versionBadge.contains(e.target)) closeVersionTip();
      },
      true
    );
    window.addEventListener('resize', function () {
      if (versionTip) placeVersionTip();
    });

    fetch('/version.json', { cache: 'no-store' })
      .then(function (res) {
        if (!res.ok) throw new Error('HTTP ' + res.status);
        return res.json();
      })
      .then(function (v) {
        if (!v || !(v.build || v.version)) return;
        webVersion = v;
        versionBadge.textContent = 'web ' + (v.build || v.version);
        versionBadge.hidden = false;
      })
      .catch(function () {
        // Нет версии — нет бейджа, остальной экран работает как раньше.
      });
  }

  // --- Чат «Спросить» (openspec add-web-chat) --------------------------------
  // Вопросы о кошельке своими словами: задание `chat` в wallet-ai, данные
  // модель берёт через wallet-mcp (wallet-ai/openspec/specs/ai-chat).
  //
  // Свой корень #chat-root в <body>, рядом с #app (D1): экраны верхнего
  // уровня перезаписывают app.innerHTML целиком и унесли бы окно с лентой.
  // Состояние — один объект chat (D2), окно рисуется из него; лента,
  // conversation_id и идущее задание живут в sessionStorage (D4), поэтому
  // переживают смену экрана и F5, но не закрытие вкладки и не «Выйти».
  // Ожидание ответа не привязано к окну (D3): ответ в свёрнутое окно
  // записывается в ленту и зажигает точку на кнопке. Устаревание попытки —
  // только по chatSeq («Новый диалог», «Выйти», смена пользователя).
  var CHAT_STORE_KEY = 'wallet.chat.v1';
  var CHAT_MAX_MESSAGES = 50;
  var CHAT_TEXT_MAX_BYTES = 1000; // предел input.text в wallet-ai (ChatInput)
  var CHAT_WAIT_LIMIT_MS = 150000; // как у бота: после — DELETE и «не успел»
  var CHAT_STALE_MS = 30 * 60 * 1000; // AI_CHAT_HISTORY_TTL_SECS wallet-ai
  var CHAT_PROVIDER_TITLE = { lmstudio: 'LM Studio', claude: 'Claude' };
  var CHAT_HINT = 'Спросите про траты, доходы и балансы: «сколько за няню в октябре?», ' +
    '«сравни продукты с прошлым месяцем».';
  var CHAT_TEXT = {
    providerUnavailable: 'Выбранный ИИ сейчас недоступен. Сменить его можно командой /ai в Telegram-боте.',
    off: 'ИИ сейчас выключен.',
    busy: 'ИИ занят, попробуйте через минуту.',
    noData: 'Не удалось получить данные кошелька, попробуйте позже.',
    refused: 'ИИ не стал отвечать на этот вопрос.',
    timeout: 'ИИ не успел ответить, попробуйте позже.',
    network: 'Не удалось связаться с ИИ, проверьте соединение.',
    generic: 'ИИ не смог ответить, попробуйте позже.',
    stale: 'Прошло больше 30 минут — ИИ не помнит вопросы выше.',
    tooLong: 'Вопрос длиннее 1000 байт — сократите его.',
  };

  var chatAvailable = false; // GET /api/ai/status объявил chat, не режим просмотра
  var chatRoot = null;
  var chatSeq = 0;
  var chatPosting = false; // POST задания в пути — второй не создаём (двойной клик)
  var chatPollingJob = null; // job_id, по которому сейчас идёт long-poll
  var chatModelTitle = null; // «Модель: …»; null — не прочитана
  var chatModelRequested = false;
  var chat = chatEmptyState(null);

  function chatNewConversationId() {
    return 'web-' + uuidV4(); // [A-Za-z0-9_:-]{1,64}, см. ChatInput wallet-ai
  }

  function chatEmptyState(user) {
    return {
      user: user, open: false, conversationId: chatNewConversationId(), messages: [],
      pending: null, // {jobId|null, startedAt, key}
      lastAnswerAt: 0, unread: false,
    };
  }

  function chatUtf8Bytes(s) {
    return unescape(encodeURIComponent(s)).length;
  }

  // Окно (open) не сохраняется: после F5 оно свёрнуто. try/catch — приватный
  // режим или заблокированное хранилище просто теряют ленту при F5.
  function chatSave() {
    if (!chat.user) return;
    chat.messages = chat.messages.slice(-CHAT_MAX_MESSAGES);
    try {
      sessionStorage.setItem(CHAT_STORE_KEY, JSON.stringify({
        user: chat.user, conversationId: chat.conversationId, messages: chat.messages,
        pending: chat.pending, lastAnswerAt: chat.lastAnswerAt, unread: chat.unread,
      }));
    } catch (e) { /* без хранилища — лента живёт до F5 */ }
  }

  function chatClearStore() {
    try { sessionStorage.removeItem(CHAT_STORE_KEY); } catch (e) { /* нечего стирать */ }
  }

  // Смена пользователя (первый вход после загрузки, вход другим человеком):
  // текущая попытка устаревает, лента — только своя из sessionStorage.
  function chatSwitchUser(user) {
    chatSeq++;
    chatPosting = false;
    chatPollingJob = null;
    chatModelTitle = null;
    chatModelRequested = false;
    chat = chatEmptyState(user);
    var saved = null;
    try { saved = JSON.parse(sessionStorage.getItem(CHAT_STORE_KEY) || 'null'); } catch (e) { saved = null; }
    if (!saved || saved.user !== user || !Array.isArray(saved.messages)) {
      chatClearStore();
      return;
    }
    if (typeof saved.conversationId === 'string' && saved.conversationId) chat.conversationId = saved.conversationId;
    chat.messages = saved.messages.slice(-CHAT_MAX_MESSAGES);
    chat.pending = saved.pending && typeof saved.pending.startedAt === 'number' ? saved.pending : null;
    chat.lastAnswerAt = typeof saved.lastAnswerAt === 'number' ? saved.lastAnswerAt : 0;
    chat.unread = saved.unread === true;
  }

  // Из refreshAiStatus: каждый заход на «Отчёты» (стартовый экран).
  function chatSetAvailable(available) {
    var user = currentUser ? currentUser.email : null;
    if (chat.user !== user) chatSwitchUser(user);
    chatAvailable = !!available && !!user && !viewAsUser;
    if (chatAvailable) {
      chatEnsureRoot();
      chatResume();
    }
    chatRender();
  }

  // renderLogin: кнопки нет, ленту не трогаем — после повторного входа тем же
  // человеком (истекла сессия) она на месте.
  function chatHide() {
    chatAvailable = false;
    chat.open = false;
    chatRender();
  }

  // «Выйти» и удаление аккаунта: ленту стираем, ждать нечего.
  function chatForget() {
    chatSeq++;
    chatPosting = false;
    chatPollingJob = null;
    chat = chatEmptyState(null);
    chatClearStore();
    chatHide();
  }

  function chatEnsureRoot() {
    if (chatRoot) return;
    chatRoot = document.createElement('div');
    chatRoot.id = 'chat-root';
    chatRoot.hidden = true;
    chatRoot.innerHTML =
      '<button type="button" class="chat-fab" id="chat-fab" aria-label="Спросить ИИ" title="Спросить ИИ">' +
      '<svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" ' +
      'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
      '<path d="M21 12a8 8 0 0 1-11.6 7.1L4 20.5l1.4-4.9A8 8 0 1 1 21 12z"/>' +
      '<path d="M9 10h6M9 13.5h4"/></svg>' +
      '<span class="chat-fab-dot" id="chat-fab-dot" hidden></span></button>' +
      '<section class="chat-panel" id="chat-panel" role="dialog" aria-labelledby="chat-title" hidden>' +
      '<header class="chat-head">' +
      '<div class="chat-head-text"><h2 id="chat-title">Спросить</h2>' +
      '<div class="chat-model" id="chat-model" hidden></div></div>' +
      '<button type="button" class="chat-head-btn" id="chat-new">Новый диалог</button>' +
      '<button type="button" class="chat-head-btn chat-collapse" id="chat-collapse" aria-label="Свернуть" title="Свернуть">' +
      '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" ' +
      'stroke-linecap="round" aria-hidden="true"><path d="M5 12h14"/></svg></button>' +
      '</header>' +
      '<div class="chat-log" id="chat-log" aria-live="polite"></div>' +
      '<form class="chat-form" id="chat-form" novalidate>' +
      '<textarea id="chat-input" rows="2" placeholder="Ваш вопрос…" aria-label="Ваш вопрос"></textarea>' +
      '<button type="submit" class="btn chat-send" id="chat-send">Спросить</button>' +
      '<p class="chat-input-err" id="chat-input-err" hidden></p>' +
      '</form>' +
      '</section>';
    document.body.appendChild(chatRoot);

    document.getElementById('chat-fab').addEventListener('click', chatOpen);
    document.getElementById('chat-collapse').addEventListener('click', chatCollapse);
    document.getElementById('chat-new').addEventListener('click', chatNewDialog);
    document.getElementById('chat-panel').addEventListener('keydown', function (ev) {
      if (ev.key === 'Escape') {
        ev.preventDefault();
        chatCollapse();
      }
    });
    document.getElementById('chat-form').addEventListener('submit', function (ev) {
      ev.preventDefault();
      chatSend();
    });
    var input = document.getElementById('chat-input');
    input.addEventListener('keydown', function (ev) {
      if (ev.key === 'Enter' && !ev.shiftKey && !ev.isComposing) {
        ev.preventDefault();
        chatSend();
      }
    });
    input.addEventListener('input', function () {
      if (chatUtf8Bytes(input.value.trim()) <= CHAT_TEXT_MAX_BYTES) chatShowInputError('');
    });
  }

  function chatShowInputError(text) {
    var el = document.getElementById('chat-input-err');
    if (!el) return;
    el.textContent = text;
    el.hidden = !text;
  }

  function chatMessageHtml(m) {
    var text = escapeHtml(m.text || '');
    if (m.role === 'user') return '<div class="chat-msg chat-msg-user">' + text + '</div>';
    if (m.role === 'error') return '<div class="chat-msg chat-msg-err">' + text + '</div>';
    if (m.role === 'divider') return '<div class="chat-divider">' + text + '</div>';
    var sign = m.provider ? CHAT_PROVIDER_TITLE[m.provider] || m.provider : '';
    return '<div class="chat-msg chat-msg-ai">' + text +
      (sign ? '<div class="chat-sign">— ' + escapeHtml(sign) + '</div>' : '') + '</div>';
  }

  // Поле ввода не перерисовывается: фокус, курсор и набранный текст живут сами.
  function chatRender() {
    if (!chatRoot) return;
    chatRoot.hidden = !chatAvailable;
    var open = chatAvailable && chat.open;
    // chat-available — для отступа липких панелей экранов под кнопку (D8).
    document.body.classList.toggle('chat-available', chatAvailable);
    document.body.classList.toggle('chat-open', open);
    document.getElementById('chat-fab').hidden = open;
    document.getElementById('chat-fab-dot').hidden = !chat.unread;
    document.getElementById('chat-panel').hidden = !open;

    var model = document.getElementById('chat-model');
    model.hidden = !chatModelTitle;
    model.innerHTML = chatModelTitle
      ? 'Модель: ' + escapeHtml(chatModelTitle) + '<span class="chat-model-hint">Сменить — /ai в Telegram-боте</span>'
      : '';

    document.getElementById('chat-send').disabled = !!chat.pending || chatPosting;

    if (!open) return;
    var log = document.getElementById('chat-log');
    var html = chat.messages.map(chatMessageHtml).join('');
    if (chat.pending) html += '<div class="chat-msg chat-msg-ai chat-pending">Думаю…</div>';
    if (!html) html = '<p class="chat-hint">' + escapeHtml(CHAT_HINT) + '</p>';
    log.innerHTML = html;
    log.scrollTop = log.scrollHeight;
  }

  function chatOpen() {
    if (!chatAvailable) return;
    chat.open = true;
    chat.unread = false;
    chatSave();
    chatRender();
    chatLoadModel();
    document.getElementById('chat-input').focus();
  }

  function chatCollapse() {
    chat.open = false;
    chatRender();
    var fab = document.getElementById('chat-fab');
    if (fab && chatAvailable) fab.focus();
  }

  // Один раз за загрузку страницы (и за пользователя): провайдер меняется в
  // боте командой /ai, на вебе его не выбирают (D6).
  function chatLoadModel() {
    if (chatModelRequested) return;
    chatModelRequested = true;
    var seq = chatSeq;
    apiFetch('/api/ai/settings', { credentials: 'include' })
      .then(function (res) { return res.ok ? res.json() : null; })
      .then(function (data) {
        if (seq !== chatSeq || !data || typeof data.provider !== 'string') return;
        var p = (Array.isArray(data.providers) ? data.providers : []).filter(function (x) {
          return x && x.id === data.provider;
        })[0];
        chatModelTitle = p && p.title ? String(p.title) : CHAT_PROVIDER_TITLE[data.provider] || data.provider;
        chatRender();
      }, function () { /* строки «Модель» просто нет */ });
  }

  function chatNewDialog() {
    if (chat.pending && chat.pending.jobId) aiDeleteJob(chat.pending.jobId);
    var user = chat.user;
    chatSeq++;
    chatPosting = false;
    chatPollingJob = null;
    chat = chatEmptyState(user);
    chat.open = true;
    chatSave();
    chatShowInputError('');
    chatRender();
    document.getElementById('chat-input').focus();
  }

  function chatSend() {
    var input = document.getElementById('chat-input');
    var text = input.value.trim();
    if (!chatAvailable || !text || chat.pending || chatPosting) return;
    if (chatUtf8Bytes(text) > CHAT_TEXT_MAX_BYTES) {
      chatShowInputError(CHAT_TEXT.tooLong);
      return;
    }
    chatShowInputError('');

    // wallet-ai забывает диалог через 30 минут — не делаем вид, что помнит
    // (требование «Устаревший диалог»).
    if (chat.lastAnswerAt && Date.now() - chat.lastAnswerAt > CHAT_STALE_MS && chat.messages.length) {
      chat.conversationId = chatNewConversationId();
      chat.messages.push({ role: 'divider', text: CHAT_TEXT.stale });
    }
    chat.messages.push({ role: 'user', text: text });
    input.value = '';

    var seq = chatSeq;
    var key = 'web-chat:' + uuidV4();
    chat.pending = { jobId: null, startedAt: Date.now(), key: key };
    chatPosting = true;
    chatSave();
    chatRender();

    var now = new Date();
    apiFetch('/api/ai/jobs', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        kind: 'chat',
        idempotency_key: key,
        input: {
          text: text,
          conversation_id: chat.conversationId,
          now: { date: isoDate(now), time: localTime(now) },
        },
      }),
    })
      .then(function (res) {
        if (res.status === 401) {
          chatPosting = false;
          if (seq === chatSeq) renderLogin();
          return null;
        }
        return res.json().catch(function () { return {}; }).then(function (data) {
          if (res.status === 202 && data && data.job_id) return data;
          var err = new Error(data && data.error ? data.error : 'HTTP ' + res.status);
          err.status = res.status;
          err.code = data && data.error;
          throw err;
        });
      })
      .then(function (data) {
        if (!data) return;
        chatPosting = false;
        if (seq !== chatSeq) {
          aiDeleteJob(data.job_id); // «Новый диалог», пока задание создавалось
          return;
        }
        chat.pending.jobId = data.job_id;
        chatSave();
        chatRender();
        chatPoll(seq, data.job_id);
      })
      .catch(function (err) {
        chatPosting = false;
        if (seq !== chatSeq) return;
        var t = CHAT_TEXT.generic;
        if (!err.status) t = CHAT_TEXT.network;
        else if (err.status === 503) t = err.code === 'provider_unavailable' ? CHAT_TEXT.providerUnavailable : CHAT_TEXT.off;
        else if (err.status === 429) t = CHAT_TEXT.busy;
        chatFinish(seq, { role: 'error', text: t });
      });
  }

  // Long-poll ?wait=25 (до 30 с таймаута гейтвея). Предел 150 с считается от
  // отправки (pending.startedAt лежит в sessionStorage — действует и после F5).
  function chatPoll(seq, jobId) {
    if (seq !== chatSeq || !chat.pending) return;
    if (Date.now() - chat.pending.startedAt > CHAT_WAIT_LIMIT_MS) {
      aiDeleteJob(jobId);
      chatFinish(seq, { role: 'error', text: CHAT_TEXT.timeout });
      return;
    }
    chatPollingJob = jobId;
    apiFetch('/api/ai/jobs/' + encodeURIComponent(jobId) + '?wait=25', { credentials: 'include' })
      .then(function (res) {
        if (seq !== chatSeq) return null;
        if (res.status === 401) {
          chatPollingJob = null; // задание ждёт: после входа и F5 опрос продолжится
          renderLogin();
          return null;
        }
        if (!res.ok) {
          var err = new Error('HTTP ' + res.status);
          err.status = res.status;
          throw err;
        }
        return res.json();
      })
      .then(function (job) {
        if (!job || seq !== chatSeq) return;
        if (job.status === 'queued' || job.status === 'running') {
          chatPoll(seq, jobId);
          return;
        }
        if (job.status === 'done' && job.result && typeof job.result.text === 'string') {
          if (typeof job.result.conversation_id === 'string' && job.result.conversation_id) {
            chat.conversationId = job.result.conversation_id;
          }
          chatFinish(seq, { role: 'ai', text: job.result.text, provider: job.result.provider || '' });
          return;
        }
        var t = CHAT_TEXT.generic;
        if (job.status === 'failed') {
          if (job.failure === 'tools_unavailable' || job.failure === 'auth_expired') t = CHAT_TEXT.noData;
          else if (job.failure === 'provider_refused') t = CHAT_TEXT.refused;
        }
        chatFinish(seq, { role: 'error', text: t });
      })
      .catch(function (err) {
        if (seq !== chatSeq) return;
        chatFinish(seq, { role: 'error', text: err.status ? CHAT_TEXT.generic : CHAT_TEXT.network });
      });
  }

  function chatFinish(seq, message) {
    if (seq !== chatSeq) return;
    chat.pending = null;
    chatPollingJob = null;
    chat.messages.push(message);
    chat.lastAnswerAt = Date.now();
    if (!chat.open) chat.unread = true;
    chatSave();
    chatRender();
  }

  // После F5 или повторного входа: задание из sessionStorage дождаться.
  // Без job_id (страницу перезагрузили, пока POST был в пути) ждать нечего.
  function chatResume() {
    if (!chat.pending || chatPosting) return;
    if (!chat.pending.jobId) {
      chatFinish(chatSeq, { role: 'error', text: CHAT_TEXT.generic });
      return;
    }
    if (chatPollingJob !== chat.pending.jobId) chatPoll(chatSeq, chat.pending.jobId);
  }

  function boot() {
    app.innerHTML = '<p class="sub">Загрузка…</p>';
    viewAsUser = null; // свежая загрузка страницы — режим просмотра прошлой сессии не переживает F5
    // См. PENDING_INVITE_TOKEN_KEY выше — откладываем ДО запроса /auth/me
    // (не после), потому что дальше по коду может последовать полный уход
    // на google.com: если пользователь ещё не залогинен, ниже покажем
    // renderJoinLogin(), а не renderLogin().
    var joinToken = parseJoinPath(location.pathname);
    if (joinToken) setPendingInviteToken(joinToken);

    apiFetch('/auth/me', { credentials: 'include' })
      .then(function (res) {
        if (res.status === 401) {
          if (joinToken) renderJoinLogin();
          else renderLogin();
          return;
        }
        if (!res.ok) throw new Error('HTTP ' + res.status);
        // Отчёты — стартовый экран (было renderDashboard — демо-CRUD
        // кошельков; см. чат про то, что дизайн предполагает пользователя,
        // который после авторизации попадает сразу в кабинет отчётов, а не
        // в служебную демо-форму). currentUser выставляется здесь же —
        // renderReports() и renderAdmin() читают её как модульную
        // переменную, не параметром.
        return res.json().then(function (user) {
          currentUser = user;
          // Приглашение — раньше остального: если оно есть, "Отчёты" должны
          // открыться УЖЕ в присоединённом леджере, а не в старом (если он
          // был) с ошибкой где-то в стороне.
          return acceptPendingInviteIfAny().then(function () {
            // Зашли по /join/<token>, уже будучи залогинены (сессия ещё не
            // истекла — обычного Google-редиректа тогда вообще не было) —
            // адресная строка не должна продолжать показывать одноразовую
            // ссылку после того, как она использована.
            if (joinToken) history.replaceState(null, '', '/');

            // hash с предыдущей загрузки (F5) — восстанавливаем именно тот
            // экран/фильтр "Отчётов", что были до перезагрузки, а не всегда
            // стартовый "Обзор" за дефолтный период. isApplyingHistoryState —
            // чтобы switchReportsView('over') внутри самой renderReports() не
            // запушил лишнюю промежуточную запись раньше restored-состояния.
            // renderReports() сама зовёт refreshPeriod() под дефолтный фильтр
            // в конце; applyReportsHistoryState() ниже зовёт его ещё раз под
            // восстановленный — двойной запрос ТОЛЬКО в этом (нечастом) случае
            // F5 с непустым hash, сознательно не устранён ради того, чтобы не
            // заводить отдельный "renderReports(skipInitialLoad)" ради одного
            // редкого пути.
            var restored = parseReportsHash(location.hash);
            isApplyingHistoryState = true;
            renderReports();
            isApplyingHistoryState = false;
            if (restored) applyReportsHistoryState(restored);
            // Одна запись истории, отражающая РЕАЛЬНО показанный экран — см.
            // replaceReportsUrlState.
            replaceReportsUrlState(reportsView);
          });
        });
      })
      .catch(function (err) {
        renderError('Не удалось связаться с сервером: ' + err.message);
      });
  }

  initVersionBadge();
  boot();
})();
