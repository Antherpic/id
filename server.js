require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const fetch = (...args) => import('node-fetch').then(({default: f}) => f(...args));

const DB_FILE = './data.sqlite';
const PORT = process.env.PORT || 3000;
const RECAPTCHA_SECRET = process.env.RECAPTCHA_SECRET || '';
const RECAPTCHA_SITEKEY = process.env.RECAPTCHA_SITEKEY || '';

if (!fs.existsSync(DB_FILE)) {
  fs.writeFileSync(DB_FILE, '');
}
const db = new sqlite3.Database(DB_FILE);

// Init DB
const initSql = fs.readFileSync(path.join(__dirname, 'db-init.sql'), 'utf8');
db.exec(initSql);

const app = express();
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static('public'));
app.set('views', path.join(__dirname, 'views'));
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev_secret',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // set true on HTTPS production
}));

function query(sql, params=[]) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => err ? reject(err) : resolve(rows));
  });
}
function get(sql, params=[]) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => err ? reject(err) : resolve(row));
  });
}
function run(sql, params=[]) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function(err) {
      if (err) return reject(err);
      resolve(this);
    });
  });
}

// Middleware: protect route
function requireLogin(req, res, next) {
  if (req.session.userId) return next();
  res.redirect('/login');
}

// Utilities
async function verifyRecaptcha(token) {
  if (!RECAPTCHA_SECRET) return false;
  const url = `https://www.google.com/recaptcha/api/siteverify`;
  const params = new URLSearchParams();
  params.append('secret', RECAPTCHA_SECRET);
  params.append('response', token);
  const r = await fetch(url, { method: 'POST', body: params });
  const json = await r.json();
  return json.success;
}

// Views (static HTML files are in /views). Use simple templating via replace
function renderFile(res, name, vars = {}) {
  const file = fs.readFileSync(path.join(__dirname, 'views', name), 'utf8');
  let out = file;
  for (const k in vars) out = out.replace(new RegExp(`{{${k}}}`, 'g'), vars[k]);
  res.send(out);
}

// Routes
app.get('/', (req, res) => {
  if (req.session.userId) {
    renderFile(res, 'dashboard.html', { email: req.session.email || '' });
  } else {
    res.redirect('/login');
  }
});

app.get('/register', (req, res) => renderFile(res, 'register.html', { RECAPTCHA_SITEKEY }));
app.post('/register', async (req, res) => {
  const { email, password, 'g-recaptcha-response': recaptchaToken } = req.body;
  if (!email || !password) return res.send('Email & password wajib.');
  if (RECAPTCHA_SECRET && !(await verifyRecaptcha(recaptchaToken))) {
    return res.send('reCAPTCHA gagal, coba lagi.');
  }
  const hash = await bcrypt.hash(password, 10);
  try {
    await run('INSERT INTO users (email, password_hash) VALUES (?, ?)', [email, hash]);
    res.send('Akun dibuat. Silakan <a href="/login">login</a>.');
  } catch (e) {
    if (e.message && e.message.includes('UNIQUE')) return res.send('Email sudah terdaftar.');
    console.error(e);
    res.send('Terjadi kesalahan.');
  }
});

app.get('/login', (req, res) => renderFile(res, 'login.html', { RECAPTCHA_SITEKEY }));
app.post('/login', async (req, res) => {
  const { email, password, 'g-recaptcha-response': recaptchaToken } = req.body;
  if (RECAPTCHA_SECRET && !(await verifyRecaptcha(recaptchaToken))) {
    return res.send('reCAPTCHA gagal, coba lagi.');
  }
  const user = await get('SELECT * FROM users WHERE email = ?', [email]);
  if (!user) return res.send('Email atau password salah.');
  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.send('Email atau password salah.');
  // Jika ada TOTP secret, lanjut ke verifikasi 2FA
  if (user.totp_secret) {
    req.session.tmpUserId = user.id;
    req.session.tmpEmail = user.email;
    return res.redirect('/2fa-verify');
  }
  // login biasa
  req.session.userId = user.id;
  req.session.email = user.email;
  res.redirect('/');
});

app.get('/forgot', (req, res) => renderFile(res, 'forgot.html', { }));
app.post('/forgot', async (req, res) => {
  const { email } = req.body;
  const user = await get('SELECT * FROM users WHERE email = ?', [email]);
  if (!user) return res.send('Jika email terdaftar, Anda akan menerima instruksi reset (demo: tidak mengirim email).');
  const token = crypto.randomBytes(24).toString('hex');
  const expiry = Date.now() + 1000 * 60 * 60; // 1 jam
  await run('UPDATE users SET reset_token = ?, reset_expiry = ? WHERE id = ?', [token, expiry, user.id]);
  // TODO: kirim link via email. Untuk demo tampil link:
  res.send(`Link reset (demo): <a href="/reset/${token}">/reset/${token}</a>`);
});

app.get('/reset/:token', (req, res) => {
  const token = req.params.token;
  renderFile(res, 'reset.html', { token });
});
app.post('/reset/:token', async (req, res) => {
  const token = req.params.token;
  const { password } = req.body;
  const user = await get('SELECT * FROM users WHERE reset_token = ?', [token]);
  if (!user || !user.reset_expiry || Date.now() > user.reset_expiry) return res.send('Token tidak valid atau sudah kadaluarsa.');
  const hash = await bcrypt.hash(password, 10);
  await run('UPDATE users SET password_hash = ?, reset_token = NULL, reset_expiry = NULL WHERE id = ?', [hash, user.id]);
  res.send('Password sudah direset. Silakan <a href="/login">login</a>.');
});

// 2FA setup (user harus login)
app.get('/2fa-setup', requireLogin, async (req, res) => {
  const user = await get('SELECT * FROM users WHERE id = ?', [req.session.userId]);
  if (!user) return res.redirect('/login');
  // generate secret
  const secret = speakeasy.generateSecret({ length: 20, name: `MyApp (${user.email})` });
  // simpan secret sementara di session sampai user verify
  req.session.temp_totp_secret = secret.base32;
  const otpauth = secret.otpauth_url;
  const qrData = await qrcode.toDataURL(otpauth);
  renderFile(res, '2fa-setup.html', { qr: qrData });
});
app.post('/2fa-setup', requireLogin, async (req, res) => {
  const { token } = req.body;
  const tempSecret = req.session.temp_totp_secret;
  if (!tempSecret) return res.send('Tidak ada secret 2FA.');
  const verified = speakeasy.totp.verify({ secret: tempSecret, encoding: 'base32', token });
  if (!verified) return res.send('Kode salah.');
  await run('UPDATE users SET totp_secret = ? WHERE id = ?', [tempSecret, req.session.userId]);
  delete req.session.temp_totp_secret;
  res.send('2FA berhasil diaktifkan. <a href="/">Dashboard</a>');
});

// 2FA verify after login
app.get('/2fa-verify', (req, res) => {
  if (!req.session.tmpUserId) return res.redirect('/login');
  renderFile(res, '2fa-verify.html', {});
});
app.post('/2fa-verify', async (req, res) => {
  const { token } = req.body;
  const tmpId = req.session.tmpUserId;
  if (!tmpId) return res.redirect('/login');
  const user = await get('SELECT * FROM users WHERE id = ?', [tmpId]);
  if (!user || !user.totp_secret) return res.redirect('/login');
  const ok = speakeasy.totp.verify({ secret: user.totp_secret, encoding: 'base32', token, window: 1 });
  if (!ok) return res.send('Kode 2FA salah.');
  // finalize login
  req.session.userId = user.id;
  req.session.email = user.email;
  delete req.session.tmpUserId;
  delete req.session.tmpEmail;
  res.redirect('/');
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

app.listen(PORT, () => console.log(`Server berjalan pada http://localhost:${PORT}`));
