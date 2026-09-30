const crypto = require('crypto');
const linksPage = require('./_links.js');

const COOKIE = 'ss_session';
const MAX_AGE = 60 * 60 * 24 * 7; // stay signed in for 7 days

const hmac = (value, secret) =>
  crypto.createHmac('sha256', secret).update(value).digest('hex');
const sha = (v) => crypto.createHash('sha256').update(v).digest();
const safeEqual = (a, b) => {
  const A = Buffer.from(a), B = Buffer.from(b);
  return A.length === B.length && crypto.timingSafeEqual(A, B);
};

function hasValidSession(req, secret) {
  const pair = (req.headers.cookie || '')
    .split(';').map((s) => s.trim())
    .find((s) => s.startsWith(COOKIE + '='));
  if (!pair) return false;
  const [exp, sig] = decodeURIComponent(pair.slice(COOKIE.length + 1)).split('.');
  if (!exp || !sig || Number(exp) < Date.now()) return false;
  return safeEqual(sig, hmac(exp, secret));
}

function loginPage(message) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Scoring Suite</title>
<style>
  :root { --bg:#f7f8fa; --surface:#fff; --ink:#1c2430; --muted:#5d6877; --line:#d9dee5; --accent:#1f4e79; --accent-ink:#fff; --error:#a02020; }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#12171e; --surface:#1a212b; --ink:#e8ecf1; --muted:#a0aab8; --line:#2c3644; --accent:#7fb0dd; --accent-ink:#10161d; --error:#ff9a9a; }
  }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--ink); font-family:"Segoe UI",system-ui,-apple-system,"Helvetica Neue",Arial,sans-serif; line-height:1.5; }
  main { max-width:420px; margin:0 auto; padding:72px 20px; }
  h1 { font-size:2rem; line-height:1.15; margin:0 0 8px; letter-spacing:-0.01em; }
  p { color:var(--muted); margin:0 0 24px; }
  label { display:block; font-weight:600; margin-bottom:6px; }
  input { width:100%; padding:12px 14px; font-size:1rem; border:1px solid var(--line); border-radius:6px; background:var(--surface); color:var(--ink); }
  input:focus-visible, button:focus-visible { outline:3px solid var(--accent); outline-offset:2px; }
  button { margin-top:14px; width:100%; padding:12px 14px; font-size:1rem; font-weight:600; border:0; border-radius:6px; background:var(--accent); color:var(--accent-ink); cursor:pointer; }
  .error { color:var(--error); margin:0 0 16px; font-weight:600; }
</style>
</head>
<body>
<main>
  <h1>Scoring Suite</h1>
  <p>Enter the access code to see the spreadsheet links.</p>
  ${message ? `<p class="error" role="alert">${message}</p>` : ''}
  <form method="post" action="/">
    <label for="code">Access code</label>
    <input id="code" name="code" type="password" autocomplete="off" autocapitalize="none" autofocus required>
    <button type="submit">View links</button>
  </form>
</main>
</body>
</html>`;
}

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Robots-Tag', 'noindex, nofollow');
  res.setHeader('Content-Type', 'text/html; charset=utf-8');

  const secret = (process.env.ACCESS_CODE || '').trim();
  if (!secret) {
    res.statusCode = 500;
    return res.end(loginPage('This site is not set up yet. The ACCESS_CODE setting is missing.'));
  }

  if (req.method === 'POST') {
    let body = req.body;
    if (typeof body === 'string') body = Object.fromEntries(new URLSearchParams(body));
    const given = String((body && body.code) || '').trim();
    if (safeEqual(sha(given), sha(secret))) {
      const exp = String(Date.now() + MAX_AGE * 1000);
      const token = `${exp}.${hmac(exp, secret)}`;
      res.setHeader('Set-Cookie',
        `${COOKIE}=${encodeURIComponent(token)}; Max-Age=${MAX_AGE}; Path=/; HttpOnly; Secure; SameSite=Lax`);
      res.statusCode = 303;
      res.setHeader('Location', '/');
      return res.end();
    }
    await new Promise((r) => setTimeout(r, 1000)); // slows down guessing
    res.statusCode = 401;
    return res.end(loginPage('That code did not work. Check it and try again.'));
  }

  if (hasValidSession(req, secret)) return res.end(linksPage);
  return res.end(loginPage());
};
