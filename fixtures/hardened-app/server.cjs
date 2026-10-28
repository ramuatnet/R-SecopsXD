/**
 * Hardened twin of fixtures/vuln-app: same surface, controls implemented.
 * Used by false-positive suppression tests (precision). Plain node:http.
 * PORT env var, default 8898. Binds 127.0.0.1 only.
 */
const http = require('node:http');

const PORT = Number(process.env.PORT || 8898);

const USERS = { admin: 'admin123', bob: 'hunter2' };

const SECURE_HEADERS = {
  'Content-Security-Policy': "default-src 'self'",
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Permissions-Policy': 'camera=(), microphone=()',
};

let loginAttempts = 0;

function html(res, status, body, extraHeaders = {}) {
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8', ...SECURE_HEADERS, ...extraHeaders });
  res.end(body);
}

const LAYOUT = (title, body) =>
  `<!doctype html>
<html><head><title>${title}</title></head>
<body>
<nav><a href="/">Home</a> <a href="/login">Login</a> <a href="/search?q=test">Search</a>
<a href="/api/orders/1">Order 1</a> <a href="/api/users/999">Profile 999</a>
<a href="/admin">Admin</a> <a href="/assets/app.js">app.js</a></nav>
${body}
</body></html>`;

function isAuthed(req) {
  const cookie = req.headers.cookie || '';
  return /session=[A-Za-z0-9]+/.test(cookie) && /authed/.test(cookie);
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://127.0.0.1:${PORT}`);
  const p = url.pathname;

  if (p === '/' && req.method === 'GET') {
    res.setHeader('Set-Cookie', 'session=guestsession42; Path=/; HttpOnly; Secure; SameSite=Lax');
    return html(res, 200, LAYOUT('Hardened Store',
      '<h1>Hardened Store</h1><p>Welcome.</p>' +
      '<form action="/search" method="get"><input name="q"><button>Search</button></form>'));
  }

  if (p === '/robots.txt') {
    res.writeHead(200, { 'Content-Type': 'text/plain', ...SECURE_HEADERS });
    return res.end('User-agent: *\nDisallow: /admin\n');
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
      loginAttempts++;
      // V10 fixed: rate limiting (429 after 5 attempts within the window)
      if (loginAttempts > 5) {
        res.writeHead(429, { 'Content-Type': 'text/html; charset=utf-8', 'Retry-After': '60', ...SECURE_HEADERS });
        return res.end('<h1>Too many attempts</h1>');
      }
      const form = new URLSearchParams(data);
      const username = form.get('username') || '';
      const password = form.get('password') || '';
      // V9 fixed: identical message regardless of whether the user exists
      if (!USERS[username] || USERS[username] !== password) {
        return html(res, 200, LAYOUT('Login', '<h1>Login</h1><p class="error">Invalid credentials.</p>'));
      }
      res.setHeader('Set-Cookie', 'session=authed-session-token; Path=/; HttpOnly; Secure; SameSite=Strict');
      res.writeHead(302, { Location: '/' });
      res.end();
    });
    return;
  }

  if (p === '/search') {
    const q = url.searchParams.get('q') || '';
    // V4 fixed: output is HTML-escaped
    const esc = q.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    return html(res, 200, LAYOUT('Search', `<h1>Results for <span>${esc}</span></h1><p>No results.</p>`));
  }

  if (p === '/api/users/999') {
    // V3 fixed: generic error, no stack trace
    res.writeHead(404, { 'Content-Type': 'application/json', ...SECURE_HEADERS });
    return res.end(JSON.stringify({ error: 'not_found', message: 'Resource not found' }));
  }

  if (p.startsWith('/api/orders/') && req.method === 'GET') {
    // V11 fixed: authorization enforced
    if (!isAuthed(req)) {
      res.writeHead(401, { 'Content-Type': 'application/json', ...SECURE_HEADERS });
      return res.end(JSON.stringify({ error: 'unauthorized' }));
    }
    const id = p.split('/')[3] || '0';
    res.writeHead(200, { 'Content-Type': 'application/json', ...SECURE_HEADERS });
    return res.end(JSON.stringify({ orderId: Number(id), item: 'Super Gadget', total: 99.99 }));
  }

  if (p === '/admin') {
    // V7 fixed: requires authentication
    if (!isAuthed(req)) {
      res.writeHead(302, { Location: '/login', ...SECURE_HEADERS });
      return res.end();
    }
    return html(res, 200, LAYOUT('Admin', '<h1>Admin Panel</h1>'));
  }

  if (p === '/assets/' || p === '/assets') {
    // V12 fixed: no directory listing
    res.writeHead(403, { 'Content-Type': 'text/plain', ...SECURE_HEADERS });
    return res.end('Forbidden');
  }

  if (p === '/assets/app.js') {
    res.writeHead(200, { 'Content-Type': 'application/javascript', ...SECURE_HEADERS });
    return res.end('console.log("hardened app");\n');
  }

  res.writeHead(404, { 'Content-Type': 'application/json', ...SECURE_HEADERS });
  res.end(JSON.stringify({ error: 'not_found' }));
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`hardened-app listening on http://127.0.0.1:${PORT}`);
});
