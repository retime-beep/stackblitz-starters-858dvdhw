'use strict';

// Run with: npm run smoke   (the server must already be running in another terminal)
const base = `http://localhost:${process.env.PORT || 3000}`;

async function call(method, path, body, token) {
  const res = await fetch(base + path, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const json = await res.json().catch(() => ({}));
  console.log(method, path, res.status, json);
  return json;
}

(async () => {
  const stamp = Date.now();
  const email = `test${stamp}@example.com`;
  const password = 'correct-horse-battery';

  await call('POST', '/signup', {
    email,
    password,
    username: `tester${String(stamp).slice(-6)}`,
  });
  const { access_token } = await call('POST', '/login', { email, password });
  await call('POST', '/servers', { name: 'My first burrow' }, access_token);
})();
