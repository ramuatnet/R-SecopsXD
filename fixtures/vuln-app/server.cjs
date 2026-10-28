/**
 * Intentionally vulnerable fixture application (ground truth in truth.json).
 * DO NOT expose beyond loopback. Plain node:http, zero dependencies.
 * PORT env var, default 8899. Binds 127.0.0.1 only.
 */
const http = require('node:http');

const PORT = Number(process.env.PORT || 8899);

const USERS = { admin: 'admin123', bob: 'hunter2' };

function html(res, status, body, extraHeaders = {}) {
  res.writeHead(status, {
    'Content-Type': 'text/html; charset=utf-8',
    Server: 'insecure-express-clone/1.0.0',
    'X-Powered-By': 'VulnMode',
    ...extraHeaders,
  });
  res.end(body);
}

const LAYOUT = (title, body, comment = '') =>
  `<!doctype html>
<html><head><title>${title}</title></head>
<body>
${comment}
<nav><a href="/">Home</a> <a href="/login">Login</a> <a href="/search?q=test">Search</a>
<a href="/api/orders/1">Order 1</a> <a href="/api/users/999">Profile 999</a>
<a href="/admin">Admin</a> <a href="/assets/app.js">app.js</a></nav>
${body}
</body></html>`;

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://127.0.0.1:${PORT}`);
  const p = url.pathname;

  if (p === '/' && req.method === 'GET') {
    res.setHeader('Set-Cookie', 'session=deadbeefc0ffee42; Path=/');
    return html(res, 200, LAYOUT(
      'VulnApp Store',
      '<h1>VulnApp Store</h1><p>Welcome to the store.</p>' +
      '<form action="/search" method="get"><input name="q"><button>Search</button></form>',
      '<!-- BUILD 2026.05.12 deployed on web-prod-07 (10.20.30.40). Internal debug endpoint: /api/debug/env - remove before GA -->',
    ));
  }

  if (p === '/robots.txt') {
    res.writeHead(200, { 'Content-Type': 'text/plain', Server: 'insecure-express-clone/1.0.0' });
    return res.end('User-agent: *\nDisallow: /admin\nDisallow: /backup.zip\n');
  }

  if (p === '/login' && req.method === 'GET') {
    return html(res, 200, LAYOUT('Login',
      '<h1>Login</h1><form action="/login" method="post">' +
      '<input name="username" placeholder="username"><input name="password" type="password">' +
      '<button>Login</button></form>'));
  }

  if (p === '/login' && req.method === 'POST') {
    let data = '';
    req.on('data', (c) => { data += c; });
    req.on('end', () => {
      const form = new URLSearchParams(data);
      const username = form.get('username') || '';
      const password = form.get('password') || '';
      if (USERS[username] === undefined) {
        return html(res, 200, LAYOUT('Login', `<h1>Login</h1><p class="error">Unknown user "${username}". Please register first.</p>`));
      }
      if (USERS[username] !== password) {
        return html(res, 200, LAYOUT('Login', `<h1>Login</h1><p class="error">Invalid password for user ${username}.</p>`));
      }
      res.setHeader('Set-Cookie', 'session=authenticated-session-token-42; Path=/');
      res.writeHead(302, { Location: '/' });
      res.end();
    });
    return;
  }

  if (p === '/search') {
    const q = url.searchParams.get('q') || '';
    // V4: q is reflected without encoding
    return html(res, 200, LAYOUT('Search', `<h1>Results for <span>${q}</span></h1><p>No results.</p>`));
  }

  if (p === '/api/users/999') {
    // V3: unhandled exception -> stack trace in response
    res.writeHead(500, { 'Content-Type': 'text/html; charset=utf-8', Server: 'insecure-express-clone/1.0.0' });
    const err = new Error('Cannot read properties of undefined (reading "profile") at UserService.getProfile (/srv/app/services/user-service.js:214:19) at /srv/app/routes/users.js:88:24');
    return res.end(`<h1>Internal Server Error</h1><pre>${err.stack}</pre>`);
  }

  if (p.startsWith('/api/orders/') && req.method === 'GET') {
    // V11: any order id is returned without any authorization check
    const id = p.split('/')[3] || '0';
    res.writeHead(200, { 'Content-Type': 'application/json', Server: 'insecure-express-clone/1.0.0' });
    return res.end(JSON.stringify({
      orderId: Number(id), item: 'Super Gadget', total: 99.99,
      customer: { name: 'Alice Example', email: 'alice@example.com', address: '1 Secret Lane' },
    }));
  }

  if (p === '/admin') {
    // V7: no authentication check
    return html(res, 200, LAYOUT('Admin',
      '<h1>Admin Panel</h1><table><tr><th>user</th><th>role</th></tr>' +
      '<tr><td>admin</td><td>superuser</td></tr><tr><td>bob</td><td>customer</td></tr></table>'));
  }

  if (p === '/assets/' || p === '/assets') {
    // V12: directory listing
    return html(res, 200, LAYOUT('Index of /assets/',
      '<h1>Index of /assets/</h1><ul><li><a href="/assets/app.js">app.js</a></li>' +
      '<li><a href="/assets/config-backup.json">config-backup.json</a></li></ul>'));
  }

  if (p === '/assets/app.js') {
    res.writeHead(200, { 'Content-Type': 'application/javascript', Server: 'insecure-express-clone/1.0.0' });
    return res.end('console.log("vuln app");\n');
  }

  html(res, 404, LAYOUT('Not found', '<h1>404</h1>'));
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`vuln-app listening on http://127.0.0.1:${PORT}`);
});
