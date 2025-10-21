const authStatus = document.getElementById('authStatus');
const loginBtn = document.getElementById('loginBtn');
const logoutBtn = document.getElementById('logoutBtn');
const getTokenBtn = document.getElementById('getTokenBtn');
const csrfTokenBox = document.getElementById('csrfTokenBox');
const form = document.getElementById('updateForm');
const resultBox = document.getElementById('resultBox');

let csrfToken = null;

loginBtn.addEventListener('click', async () => {
  const r = await fetch('/login', { method: 'POST', headers: { 'Content-Type': 'application/json' } , credentials: 'include' });
  const j = await r.json();
  authStatus.textContent = j.ok ? 'Logged in (demo session set).' : 'Login failed';
});

logoutBtn.addEventListener('click', async () => {
  await fetch('/logout', { method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'include' });
  csrfToken = null;
  csrfTokenBox.textContent = '—';
  authStatus.textContent = 'Logged out.';
});

getTokenBtn.addEventListener('click', async () => {
  const r = await fetch('/csrf-token', { credentials: 'include' });
  const j = await r.json();
  if (j.csrfToken) {
    csrfToken = j.csrfToken;
    csrfTokenBox.textContent = csrfToken;
  } else {
    csrfTokenBox.textContent = JSON.stringify(j, null, 2);
  }
});

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  if (!csrfToken) {
    resultBox.textContent = 'Get the CSRF token first.';
    return;
  }
  const payload = {
    email: document.getElementById('email').value,
    bio: document.getElementById('bio').value,
    currentPassword: document.getElementById('pwd').value || undefined
  };
  const r = await fetch('/api/profile/update', {
    method: 'POST',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      'X-Requested-With': 'XMLHttpRequest',
      'X-CSRF-Token': csrfToken
    },
    body: JSON.stringify(payload)
  });
  const j = await r.json();
  resultBox.textContent = JSON.stringify(j, null, 2);
});
