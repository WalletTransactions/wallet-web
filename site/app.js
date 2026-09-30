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
  //  - GET /api/reports/admin/users (wallet-report) — кошельки/операции/
  //    даты операций/участники леджера.
  // Два отдельных сервиса, две отдельные базы (см. README wallet-report,
  // "Админ: агрегаты по пользователям...") — сшивание на клиенте вместо
  // похода одного сервиса в базу другого, тем же принципом разделения, что
  // и весь остальной проект. Один из двух ответов может не содержать
  // строку для какого-то user_id (например, пользователь ни разу не
  // синкал ни с одного устройства и потому ещё не владеет ни одним
  // леджером) — statsByUserId.hasOwnProperty ниже, а не users.find,
  // молча подставляет пустые счётчики в этом случае, не роняя всю таблицу.
  function renderAdmin() {
    app.innerHTML = '<p class="sub">Загрузка…</p>';

    var usersPromise = apiFetch('/admin/users', { credentials: 'include' }).then(function (res) {
      if (res.status === 401) { renderLogin(); return null; }
      return res.json().then(function (data) {
        if (!res.ok) throw new Error(data && data.error ? data.error : 'HTTP ' + res.status);
        return data;
      });
    });
    // /api/reports/admin/users может ответить пустым списком (ни у кого нет
    // леджера) — это не ошибка; сетевой сбой ЭТОГО запроса при этом не
    // должен уронить всю таблицу пользователей (email/роль важнее и без
    // него) — .catch превращает отказ в пустой список статистики, ниже
    // просто не будет колонок кошельков/операций для НИКОГО.
    var statsPromise = apiFetch('/api/reports/admin/users', { credentials: 'include' })
      .then(function (res) {
        if (!res.ok) return { users: [] };
        return res.json();
      })
      .catch(function () { return { users: [] }; });

    Promise.all([usersPromise, statsPromise])
      .then(function (results) {
        var usersData = results[0];
        if (!usersData) return; // 401 — renderLogin() уже вызван внутри usersPromise
        var statsData = results[1];

        var statsByUserId = {};
        statsData.users.forEach(function (s) { statsByUserId[s.user_id] = s; });

        renderAdminTable(usersData.users.map(function (u) {
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

  function renderAdminTable(users) {
    setWide(true);
    var rows = users
      .map(function (u) {
        return (
          '<tr>' +
          '<td>' + escapeHtml(u.email) + '</td>' +
          '<td>' + escapeHtml(u.name) + '</td>' +
          '<td>' + roleBadgeHtml(u.role) + '</td>' +
          '<td>' + (u.email_verified ? 'да' : 'нет') + '</td>' +
          '<td>' + adminCellText(u.created_at) + '</td>' +
          '<td>' + adminCellText(u.last_login_at) + '</td>' +
          '<td>' + (u.active_sessions || 0) + '</td>' +
          '<td>' + (u.wallet_count === '' ? '—' : escapeHtml(u.wallet_count)) + '</td>' +
          '<td>' + (u.operation_count === '' ? '—' : escapeHtml(u.operation_count)) + '</td>' +
          '<td>' + adminCellText(u.first_operation_date) + '</td>' +
          '<td>' + adminCellText(u.last_operation_date) + '</td>' +
          '<td>' + (u.member_count === '' ? '—' : escapeHtml(u.member_count)) + '</td>' +
          '<td><code>' + escapeHtml(u.id) + '</code></td>' +
          '<td>' +
          '<button type="button" class="btn-view-as" data-user-id="' + escapeHtml(u.id) +
          '" data-user-email="' + escapeHtml(u.email) + '">Посмотреть как клиент</button> ' +
          '<button type="button" class="btn-force-logout" data-user-id="' + escapeHtml(u.id) +
          '" data-user-email="' + escapeHtml(u.email) + '">Разлогинить</button>' +
          '</td>' +
          '</tr>'
        );
      })
      .join('');

    app.innerHTML =
      '<h1>Пользователи</h1>' +
      '<p class="sub">Всего: ' + users.length + '. Клик по заголовку столбца сортирует таблицу.</p>' +
      '<div class="users-table-wrap">' +
      '<table class="users" id="users-table">' +
      '<thead><tr>' +
      '<th>Email<span class="arrow"></span></th>' +
      '<th>Имя<span class="arrow"></span></th>' +
      '<th>Роль<span class="arrow"></span></th>' +
      '<th>Email подтверждён<span class="arrow"></span></th>' +
      '<th>Регистрация<span class="arrow"></span></th>' +
      '<th>Последний вход<span class="arrow"></span></th>' +
      '<th>Активных сессий<span class="arrow"></span></th>' +
      '<th>Кошельков<span class="arrow"></span></th>' +
      '<th>Операций<span class="arrow"></span></th>' +
      '<th>Первая операция<span class="arrow"></span></th>' +
      '<th>Последняя операция<span class="arrow"></span></th>' +
      '<th>Участников леджера<span class="arrow"></span></th>' +
      '<th>ID<span class="arrow"></span></th>' +
      '<th>Действия<span class="arrow"></span></th>' +
      '</tr></thead>' +
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

  // Сортировка кликом по заголовку — перенесено как есть из бывшей
  // server-rendered страницы (google-auth/src/pages.cpp, до переезда сюда).
  function wireAdminTableSorting() {
    var table = document.getElementById('users-table');
    if (!table) return;
    var tbody = table.tBodies[0];
    var headers = table.tHead.rows[0].cells;

    Array.prototype.forEach.call(headers, function (th, colIndex) {
      th.addEventListener('click', function () {
        var ascending = th.getAttribute('data-order') !== 'asc';

        Array.prototype.forEach.call(headers, function (other) {
          other.removeAttribute('data-order');
          other.classList.remove('sorted');
          other.querySelector('.arrow').textContent = '';
        });
        th.setAttribute('data-order', ascending ? 'asc' : 'desc');
        th.classList.add('sorted');
        th.querySelector('.arrow').textContent = ascending ? '▲' : '▼';

        var rows = Array.prototype.slice.call(tbody.rows);
        rows.sort(function (rowA, rowB) {
          var a = rowA.cells[colIndex].textContent.trim().toLowerCase();
          var b = rowB.cells[colIndex].textContent.trim().toLowerCase();
          if (a === b) return 0;
          var cmp = a < b ? -1 : 1;
          return ascending ? cmp : -cmp;
        });
        rows.forEach(function (row) { tbody.appendChild(row); });
      });
    });
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
  function iconGridHtml(icons) {
    if (icons.length === 0) return '<p class="wallet-empty">Иконок нет.</p>';
    return (
      '<div class="icon-admin-grid">' +
      icons
        .map(function (i) {
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

  function renderAdminIconsScreen(commonIcons, users) {
    setWide(true);
    var userOptions = users
      .map(function (u) { return '<option value="' + escapeHtml(u.id) + '">' + escapeHtml(u.email) + '</option>'; })
      .join('');

    app.innerHTML =
      '<h1>Иконки</h1>' +
      '<p class="sub">Общий набор виден всем кошелькам. Выберите пользователя, чтобы ' +
      'посмотреть его собственные иконки (добавленные им самим из галереи).</p>' +
      '<h2>Общие</h2>' +
      iconGridHtml(commonIcons) +
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
        var container = document.getElementById('settings-devices');
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

  function deviceRowHtml(d) {
    var name = d.device_name ? escapeHtml(d.device_name) : (d.platform ? '(без имени)' : 'Браузер');
    var platform = d.platform ? escapeHtml(d.platform) : '—';
    var status = d.is_current ? '<span class="badge ok">Текущее</span>' : '';
    var action = d.is_current
      ? '<span class="sub-id">выйдите через «Выйти»</span>'
      : '<button type="button" class="btn-force-logout" data-token-hash="' +
        escapeHtml(d.token_hash) + '">Отозвать</button>';
    return (
      '<tr' + (d.is_current ? ' class="device-current"' : '') + '>' +
      '<td>' + name + '</td>' +
      '<td>' + platform + '</td>' +
      '<td>' + status + '</td>' +
      '<td>' + action + '</td>' +
      '</tr>'
    );
  }

  function renderSettingsDevicesTable(deviceList) {
    var container = document.getElementById('settings-devices');
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

      if (!window.confirm('Отозвать эту сессию? Устройство перестанет продлевать вход ' +
          'на нём, а его текущий доступ к этому сайту прервётся сразу — но доступ к ' +
          'кошелькам/отчётам ещё до 15 минут (см. README google-auth).')) {
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
        'перестанут продлевать вход.')) {
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
    listEl.innerHTML = currencyDirectory
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
      '<div id="settings-devices"><p class="sub">Загрузка…</p></div>' +
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
        return res.json().then(function (data) {
          if (!res.ok) throw new Error(data && data.error ? data.error : 'HTTP ' + res.status);
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

  function renderCurrencyPickerList() {
    var listEl = document.getElementById('currency-picker-list');
    if (!listEl) return;
    var current = eqCurrencyValue();
    listEl.innerHTML = currencyDirectory
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
  // запросу — "валюта эквивалента справочником") — грузится ОДИН раз при
  // открытии "Отчётов" (см. конец renderReports()), не при каждом
  // refreshPeriod(): список валют леджера не зависит от периода/фильтров.
  // Пока ответ не пришёл, #eq-currency держит "USD" из разметки (см.
  // renderReports) — с ним отчёты открываются сразу, кнопка пикера при этом
  // показывает пустой флаг-заглушку (currencyDirectory ещё пуст).
  function loadCurrencies() {
    fetchReport('currencies', {})
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
        // Заглушка "USD" могла не совпасть ни с одной реальной валютой этого
        // леджера (у него может не быть USD вовсе) — тогда молча остались бы
        // висеть под несуществующей валютой. Вместо этого явно берём первую
        // валюту справочника (ORDER BY iso_code на сервере, см.
        // reports_repo.hpp) и перезапрашиваем период под неё — иначе KPI на
        // "Обзоре" продолжали бы грузиться под "USD" и, если её правда нет,
        // падать 400 "неизвестный ISO-код".
        if (isoList.length && isoList.indexOf(current) < 0) {
          selectCurrency(isoList[0]); // сам зовёт renderCurrencyPickerButton()+refreshPeriod()
        }
      })
      .catch(function () { /* справочник недоступен — молча остаёмся со значением по умолчанию */ });
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
      kpiTileHtml('Остаток', (balance.incomplete ? '~ ' : '') + fmtEq(balance.total_eq), '', 'на конец периода');
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
  function renderMonthlyBalanceLine(chartEl, colSelector, months, balances) {
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

    var vals = balances.map(function (b) { return parseFloat(b.total_eq) || 0; });
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
      '<svg class="month-chart-balance-svg" width="' + w + '" height="' + h + '">' +
      '<polyline points="' + polylinePoints + '"></polyline>' + circles + '</svg>';
    chartEl.appendChild(wrap.firstChild);
  }

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
    return categoryIconHtml(r.icon_sha256, 'ops-row-icon');
  }

  function opsRowHtml(r) {
    var name = r.comment ? r.comment : (r.kind === 'transfer' ? r.from_name + ' → ' + r.to_name : r.category_name);
    var sub = r.kind === 'transfer' ? (r.from_name + ' → ' + r.to_name) : (r.category_name + ' · ' + r.wallet_name);
    if (sub === name) sub = ''; // transfer без комментария — не повторять один и тот же "A → B" дважды
    var sign = r.kind === 'expense' ? '−' : r.kind === 'income' ? '+' : '';
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

  function renderOpsFilters(filteredCount) {
    var el = document.getElementById('ops-filters');
    var s = opsState;
    var typeButtons = OPS_TYPES.map(function (t) {
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
      '<div class="ops-toolbar-row">' +
      '<div class="ops-seg-group">' + typeButtons + '</div>' +
      '<button type="button" class="link-btn" data-ops-action="clear">Сбросить</button>' +
      '</div>' +
      '<div class="ops-chip-group">' + catChips + '</div>' +
      '<div class="ops-chip-group ops-chip-group-wal">' + walChips +
      '<span class="ops-count">Найдено ' + filteredCount + '</span>' +
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
    var name = sel.comment ? sel.comment : (sel.kind === 'transfer' ? sel.from_name + ' → ' + sel.to_name : sel.category_name);
    var kindLabel = sel.kind === 'expense' ? 'Расход' : sel.kind === 'income' ? 'Доход' : 'Перевод';
    var sign = sel.kind === 'expense' ? '−' : sel.kind === 'income' ? '+' : '';
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
      if (action === 'type') { opsState.type = value; opsState.limit = 60; }
      else if (action === 'cat') { opsState.cat = value || null; opsState.limit = 60; }
      else if (action === 'wal') { opsState.wal = value || null; opsState.limit = 60; }
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

  // Держать в паре с .treemap-container{height:...} в style.css — squarify
  // должен знать РЕАЛЬНУЮ высоту контейнера в px, а не вычитывать её из CSS
  // (доставать computed style ради одного числа, которое мы сами и задали,
  // усложнение без пользы).
  var TREEMAP_HEIGHT = 380;

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
    var rects = squarifyTreemap(
      sized.map(function (c) { return parseFloat(c.amount_eq); }),
      containerW,
      TREEMAP_HEIGHT
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

  function walletTagHtml(w, endEq) {
    if (w.is_archived) return '<span class="wallet-tag wallet-tag-archived">архивный</span>';
    if (endEq === '') return '<span class="wallet-tag wallet-tag-norate">нет курса</span>';
    return '';
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
      '</span>' + walletTagHtml(w, r.endEq) + '</div>' +
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
    el.innerHTML = sortWalletRows(filtered).map(walletRowHtml).join('');
  }

  function renderWalletKpis(balStart, balEnd, wallets) {
    var el = document.getElementById('wallet-kpis');
    if (!el) return;
    // parseFloat здесь — как и в renderOverviewKpis, ТОЛЬКО ради разницы двух
    // уже посчитанных сервером сумм для показа стрелки/подписи, не для
    // хранения или дальнейшего суммирования денег (см. reports_repo.hpp,
    // "деньги — numeric").
    var delta = parseFloat(balEnd.total_eq) - parseFloat(balStart.total_eq);
    var deltaSub = (delta >= 0 ? 'выросло на ' : 'уменьшилось на ') + fmtEq(Math.abs(delta).toFixed(2));
    var activeCount = wallets.filter(function (w) { return !w.is_archived; }).length;
    var archivedCount = wallets.length - activeCount;

    el.innerHTML =
      kpiTileHtml('Всего в кошельках', (balEnd.incomplete ? '~ ' : '') + fmtEq(balEnd.total_eq), '',
        'эквивалент в ' + eqCurrencySymbol() + ' на конец периода') +
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
      if (w.is_archived) return;
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

  function renderCurList() {
    var root = document.getElementById('cur-root');
    if (!root) return;
    root.innerHTML =
      '<section class="report-section">' +
      '<div class="wallet-search-row"><input type="text" id="cur-search" ' +
      'placeholder="Пара или валюта (например EUR)" value="' + escapeHtml(curQuery) + '"></div>' +
      '<button type="button" class="btn btn-secondary" id="cur-toggle-add-btn">' +
      (curAddFormOpen ? 'Скрыть форму' : 'Добавить пару') + '</button>' +
      curAddFormHtml() +
      '<div class="users-table-wrap">' +
      '<table class="users" id="cur-table">' +
      '<thead><tr><th>Пара</th><th>Последний курс</th><th>Изменение</th><th>Действия</th></tr></thead>' +
      '<tbody id="cur-rows"></tbody>' +
      '</table></div>' +
      '</section>';
    renderCurRows();
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
        ['cur', 'Курсы валют', true],
        ['acc', 'Доступ и приглашения', true],
        ['icons', 'Иконки', true],
    ] },
  ];

  // Экраны, реально построенные в разметке renderReports() (см. ниже) —
  // общий список для switchReportsView (что скрывать/показывать) и
  // parseReportsHash (что можно восстановить из hash при F5). Раньше это
  // был буквальный литерал в обоих местах — вынесен один раз, чтобы
  // добавление вкладки не значило править два места по отдельности.
  var REPORTS_BUILT_VIEWS = ['over', 'ops', 'struct', 'dyn', 'cats', 'wal', 'cur', 'acc', 'icons'];

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
    cur: ['Курсы валют', 'Валютные пары и история их курса — добавление, изменение и удаление вручную'],
    acc: ['Доступ и приглашения', 'Кто видит этот кошелёк и как пригласить ещё одного человека'],
    icons: ['Иконки', 'Все иконки, доступные этому кошельку: общий набор и добавленные вами'],
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
    return '#/reports/' + state.view + '?' + query;
  }

  // Разбор location.hash в то же состояние — используется только при самой
  // первой загрузке страницы (см. boot()), чтобы F5 на "Отчётах" вернул тот
  // же экран/фильтр, а не всегда стартовый "Обзор" с фильтром по умолчанию.
  function parseReportsHash(hash) {
    var m = /^#\/reports\/([a-z]+)\?(.*)$/.exec(hash || '');
    if (!m || REPORTS_BUILT_VIEWS.indexOf(m[1]) < 0) return null;
    var params = {};
    m[2].split('&').forEach(function (pair) {
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
      '" data-view="' + view + '">' + escapeHtml(label) + '</button>'
    );
  }

  function reportsNavHtml() {
    return REPORTS_NAV.map(function (g) {
      var label = g.group ? '<div class="nav-group-label">' + escapeHtml(g.group) + '</div>' : '';
      var items = g.items.map(function (it) { return reportsNavItemHtml(it[0], it[1], it[2]); }).join('');
      return '<div class="nav-group">' + label + items + '</div>';
    }).join('');
  }

  // Переключение вкладки БЕЗ повторного запроса — все четыре (Обзор/Список
  // операций/Структура/Динамика) уже загружены целиком при открытии
  // "Отчётов" (см. refreshPeriod() внизу renderReports()), здесь только
  // видимость и заголовок/активный пункт меню.
  function switchReportsView(view) {
    reportsView = view;
    REPORTS_BUILT_VIEWS.forEach(function (v) {
      document.getElementById('view-' + v).hidden = v !== view;
    });
    Array.prototype.forEach.call(document.querySelectorAll('.nav-item[data-view]'), function (btn) {
      btn.classList.toggle('active', btn.getAttribute('data-view') === view);
    });
    var t = REPORTS_TITLES[view];
    document.getElementById('reports-title').textContent = t[0];
    document.getElementById('reports-subtitle').textContent = t[1];
    // Карта расходов меряет РЕАЛЬНУЮ ширину контейнера (clientWidth) — пока
    // вкладка была скрыта (hidden -> display:none), ширина читалась бы как 0.
    // Пересчитываем именно в момент, когда контейнер становится видимым.
    if (view === 'struct') renderTreemapIfVisible();
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
    // .reports-main меняет ширину вместе со свёрнутым сайдбаром (CSS-
    // transition на width, см. style.css) — карта расходов должна
    // пересчитать плитки под НОВУЮ ширину контейнера, но только когда
    // анимация реально закончится (clientWidth сразу после toggle ещё
    // покажет старое значение, транзишн только начался).
    var sidebar = document.querySelector('.reports-sidebar');
    if (sidebar) {
      var onEnd = function (ev) {
        if (ev.propertyName !== 'width') return;
        sidebar.removeEventListener('transitionend', onEnd);
        renderTreemapIfVisible();
      };
      sidebar.addEventListener('transitionend', onEnd);
    }
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
      '<header class="reports-header">' +
      viewAsBannerHtml() +
      '<div class="reports-header-top">' +
      '<button type="button" class="sidebar-toggle-btn" id="sidebar-toggle-btn" ' +
      'title="Свернуть/показать меню" aria-label="Свернуть/показать меню">☰</button>' +
      '<button type="button" class="reports-back-btn" id="reports-back-btn" hidden>← Назад</button>' +
      '<h1 id="reports-title"></h1>' +
      '</div>' +
      '<div class="reports-subtitle" id="reports-subtitle"></div>' +
      '<div class="reports-controls" style="margin-top:14px">' +
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
      '<div id="view-cur" hidden>' +
      '<div id="cur-root"><p class="sub">Загрузка…</p></div>' +
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
      '</div>' +
      '</main>' +
      '</div>';

    switchReportsView(reportsView); // проставляет заголовок/активный пункт — саму разметку уже вставили выше
    wireAvatarFallback(currentUser);
    document.getElementById('sidebar-toggle-btn').addEventListener('click', function () {
      setSidebarCollapsed(!isSidebarCollapsed());
    });

    document.getElementById('settings-link-btn').addEventListener('click', renderSettings);
    document.getElementById('logout-btn').addEventListener('click', function () {
      fetch('/auth/logout', { method: 'POST', credentials: 'include' }).then(function () {
        viewAsUser = null; // не переживает выход — следующий вход (даже другим человеком) не должен унаследовать чужой режим просмотра
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
      btn.addEventListener('click', function () { switchReportsView(btn.getAttribute('data-view')); });
    });

    wireOpsEvents();
    wireOpsInfiniteScroll();
    wireCatsEvents();
    wireWalletEvents();
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
    document.getElementById('period-refresh-btn').addEventListener('click', function () {
      reportsCache = {};
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

    return apiJson('/api/invites/accept', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: token }),
    })
      .then(function (result) {
        clearPendingInviteToken();
        if (result) window.alert('Приглашение принято — теперь у вас есть доступ к этому кошельку.');
      })
      .catch(function (err) {
        clearPendingInviteToken();
        // 409 — самая частая и самая непрозрачная причина ("почему я не вижу
        // операций владельца?"): у принимающего уже есть свой кошелёк, и
        // приглашение НЕ применилось (см. invites_repo::accept_invite,
        // AcceptStatus::kAlreadyHasLedger — ссылка при этом остаётся рабочей
        // для кого-то другого). Без явного объяснения пользователь просто
        // остаётся в своём (обычно пустом) кошельке и не понимает, почему
        // общий доступ "не сработал".
        if (err.status === 409) {
          window.alert(
            'Приглашение не применено: у вас уже есть свой кошелёк, поэтому вы ' +
              'продолжите видеть только свои операции, а не операции владельца ' +
              'приглашения. Ссылка ещё действительна и её можно передать тому, у ' +
              'кого своего кошелька нет.'
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
      });
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

  boot();
})();
