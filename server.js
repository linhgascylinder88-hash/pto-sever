// ПТО «Север» — сервер: вход по логину/паролю + прокси ZVENO + раздача приложения.
// Все секреты берутся ТОЛЬКО из переменных окружения Render (в коде их нет):
//   ZVENO_KEY   — ключ ZVENO
//   APP_LOGIN   — логин для входа
//   APP_PASSWORD— пароль для входа
//   AUTH_SECRET — произвольная длинная строка для подписи токена сессии (любой набор символов)

const http = require('http');
const https = require('https');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const ZVENO_KEY = process.env.ZVENO_KEY || '';
const ZVENO_URL = process.env.ZVENO_URL || 'https://api.zveno.ai/v1/chat/completions';
const APP_LOGIN = process.env.APP_LOGIN || '';
const APP_PASSWORD = process.env.APP_PASSWORD || '';
const AUTH_SECRET = process.env.AUTH_SECRET || 'change-me-secret';
// Файл общей базы. На Render с Persistent Disk укажите DATA_DIR=/var/data (путь смонтированного диска).
// Без диска файл лежит рядом с сервером (на бесплатном плане может сбрасываться при передеплое).
const DATA_DIR = process.env.DATA_DIR || __dirname;
const DATA_FILE = path.join(DATA_DIR, 'pto_data_sever.json');

const MIME = { '.html':'text/html; charset=utf-8', '.bat':'text/plain', '.md':'text/markdown; charset=utf-8', '.txt':'text/plain; charset=utf-8' };

// --- токен сессии: подписанная метка времени (живёт 12 часов) ---
function makeToken(){
  const exp = Date.now() + 12*60*60*1000;
  const sig = crypto.createHmac('sha256', AUTH_SECRET).update(String(exp)).digest('hex');
  return exp + '.' + sig;
}
function checkToken(tok){
  if(!tok) return false;
  const [exp, sig] = tok.split('.');
  if(!exp || !sig) return false;
  if(Date.now() > Number(exp)) return false;
  const good = crypto.createHmac('sha256', AUTH_SECRET).update(String(exp)).digest('hex');
  return safeEqual(sig, good);
}
// Сравнение строк, устойчивое к таймингу И к разной байтовой длине (кириллица/UTF-8)
function safeEqual(a, b){
  const ba = Buffer.from(String(a), 'utf8'), bb = Buffer.from(String(b), 'utf8');
  if(ba.length !== bb.length) return false;
  try{ return crypto.timingSafeEqual(ba, bb); }catch(e){ return false; }
}
function getCookie(req, name){
  const c = req.headers.cookie || '';
  const m = c.match(new RegExp('(?:^|; )'+name+'=([^;]+)'));
  return m ? decodeURIComponent(m[1]) : '';
}

// --- HTML страницы входа ---
const LOGIN_PAGE = (err)=>`<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Вход — ПТО «Север»</title>
<style>body{margin:0;font-family:system-ui,Arial,sans-serif;background:linear-gradient(135deg,#1F4E78,#2c6aa0);height:100vh;display:flex;align-items:center;justify-content:center}
.box{background:#fff;border-radius:16px;padding:34px 30px;width:330px;box-shadow:0 12px 40px rgba(0,0,0,.3)}
h1{color:#1F4E78;font-size:20px;margin:0 0 4px}.sub{color:#64748b;font-size:13px;margin-bottom:20px}
label{display:block;font-size:13px;color:#334155;margin:10px 0 4px;font-weight:600}
input{width:100%;box-sizing:border-box;padding:11px;border:1px solid #cbd5e1;border-radius:9px;font-size:15px}
button{width:100%;margin-top:18px;padding:12px;background:#1F4E78;color:#fff;border:0;border-radius:9px;font-size:15px;font-weight:600;cursor:pointer}
button:hover{background:#163a5c}.err{background:#fee2e2;color:#991b1b;padding:9px;border-radius:8px;font-size:13px;margin-bottom:12px;text-align:center}</style></head>
<body><form class="box" method="POST" action="/login">
<h1>🏗️ ПТО «Север»</h1><div class="sub">Спорткомплекс «Север» · Бассейн · 082.024</div>
${err?'<div class="err">'+err+'</div>':''}
<label>Логин</label><input name="login" autocomplete="username" autofocus>
<label>Пароль</label><input name="password" type="password" autocomplete="current-password">
<button type="submit">Войти</button></form></body></html>`;

const server = http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }

  const authed = checkToken(getCookie(req, 'pto_auth'));

  // --- ОБРАБОТКА ВХОДА ---
  if (req.url === '/login' && req.method === 'POST') {
    let body=''; req.on('data',c=>{body+=c; if(body.length>1e4) req.destroy();});
    req.on('end', ()=>{
      const p = new URLSearchParams(body);
      const login = p.get('login')||'', pass = p.get('password')||'';
      if(!APP_LOGIN || !APP_PASSWORD){ res.writeHead(500,{'Content-Type':'text/html; charset=utf-8'}); return res.end(LOGIN_PAGE('На сервере не заданы APP_LOGIN / APP_PASSWORD')); }
      // сравнение, устойчивое к таймингу и к UTF-8 (кириллица)
      const okL = safeEqual(login, APP_LOGIN);
      const okP = safeEqual(pass, APP_PASSWORD);
      if(okL && okP){
        const tok = makeToken();
        res.writeHead(302, {'Set-Cookie':'pto_auth='+encodeURIComponent(tok)+'; Path=/; HttpOnly; SameSite=Lax; Max-Age=43200', 'Location':'/'});
        return res.end();
      }
      res.writeHead(401, {'Content-Type':'text/html; charset=utf-8'});
      res.end(LOGIN_PAGE('Неверный логин или пароль'));
    });
    return;
  }

  // --- ВЫХОД ---
  if (req.url === '/logout') {
    res.writeHead(302, {'Set-Cookie':'pto_auth=; Path=/; Max-Age=0', 'Location':'/'});
    return res.end();
  }

  // --- СТРАНИЦА ВХОДА (если не авторизован) ---
  if (!authed) {
    res.writeHead(200, {'Content-Type':'text/html; charset=utf-8'});
    return res.end(LOGIN_PAGE(''));
  }

  // === ДАЛЬШЕ — только для авторизованных ===

  // --- ОБЩАЯ БАЗА: загрузка ---
  if (req.url === '/api/data' && req.method === 'GET') {
    fs.readFile(DATA_FILE, 'utf8', (err, data) => {
      res.writeHead(200, {'Content-Type':'application/json; charset=utf-8'});
      res.end(err ? '{}' : (data || '{}'));
    });
    return;
  }
  // --- ОБЩАЯ БАЗА: сохранение ---
  if (req.url === '/api/data' && req.method === 'POST') {
    let body=''; req.on('data',c=>{body+=c; if(body.length>2e7) req.destroy();});
    req.on('end', ()=>{
      // простая проверка, что это JSON
      try { JSON.parse(body); } catch(e){ res.writeHead(400,{'Content-Type':'application/json'}); return res.end(JSON.stringify({error:'invalid json'})); }
      fs.writeFile(DATA_FILE, body, 'utf8', err => {
        if(err){ res.writeHead(500,{'Content-Type':'application/json'}); return res.end(JSON.stringify({error:'write failed: '+err.message})); }
        res.writeHead(200,{'Content-Type':'application/json'}); res.end(JSON.stringify({ok:true,saved:body.length}));
      });
    });
    return;
  }

  // ПРОКСИ к ZVENO
  if (req.url === '/api/chat' && req.method === 'POST') {
    if (!ZVENO_KEY) { res.writeHead(500,{'Content-Type':'application/json'}); return res.end(JSON.stringify({error:'ZVENO_KEY не задан в окружении сервера'})); }
    let body=''; req.on('data',c=>{body+=c; if(body.length>5e6) req.destroy();});
    req.on('end', ()=>{
      const u = new URL(ZVENO_URL);
      const opt = { method:'POST', hostname:u.hostname, path:u.pathname, headers:{ 'Content-Type':'application/json', 'Authorization':'Bearer '+ZVENO_KEY, 'Content-Length':Buffer.byteLength(body) } };
      const pr = https.request(opt, pres=>{ res.writeHead(pres.statusCode,{'Content-Type':'application/json'}); pres.pipe(res); });
      pr.on('error', e=>{ res.writeHead(502,{'Content-Type':'application/json'}); res.end(JSON.stringify({error:'proxy error: '+e.message})); });
      pr.write(body); pr.end();
    });
    return;
  }

  // РАЗДАЧА ПРИЛОЖЕНИЯ
  let file = req.url === '/' ? '/PTO_SEVER_APP.html' : decodeURIComponent(req.url.split('?')[0]);
  const full = path.join(__dirname, path.normalize(file).replace(/^(\.\.[\/\\])+/, ''));
  fs.readFile(full, (err, data)=>{
    if(err){ res.writeHead(404,{'Content-Type':'text/plain; charset=utf-8'}); return res.end('Не найдено: '+file); }
    res.writeHead(200, {'Content-Type': MIME[path.extname(full).toLowerCase()] || 'application/octet-stream'});
    res.end(data);
  });
});

server.listen(PORT, ()=>console.log('ПТО Север сервер на порту '+PORT));
