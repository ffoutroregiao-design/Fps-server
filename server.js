// Servidor online do FPS Base (WebSocket). Roda no Render.
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 8080;
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, 'accounts.json');
const ADMIN_KEY = 'lkznx';   // conta dona
const MAX_HP = 100;
const TICK_MS = 50;          // envia a lista de jogadores 20 vezes por segundo

// ---------- contas ----------
let accounts = {};
try { accounts = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); } catch (e) { accounts = {}; }
function saveAccounts() {
  try { fs.writeFileSync(DATA_FILE, JSON.stringify(accounts)); }
  catch (e) { console.error('Falha ao salvar contas:', e.message); }
}
function hashPass(pass, salt) {
  return crypto.pbkdf2Sync(pass, salt, 100000, 32, 'sha256').toString('hex');
}
function checkPass(acc, pass) {
  const a = Buffer.from(hashPass(pass, acc.salt), 'hex');
  const b = Buffer.from(acc.hash, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// ---------- jogadores ----------
const byWs = new Map();   // ws -> jogador
const byId = new Map();   // id -> jogador
let nextId = 1;

const num = v => (Number.isFinite(Number(v)) ? Number(v) : 0);
const clamp = (v, lo, hi) => Math.min(hi, Math.max(lo, v));
const vec3 = a => Array.isArray(a) && a.length === 3 && a.every(Number.isFinite);

function send(ws, obj) { if (ws.readyState === 1) ws.send(JSON.stringify(obj)); }
function broadcast(obj, except) {
  const s = JSON.stringify(obj);
  for (const ws of byWs.keys()) if (ws !== except && ws.readyState === 1) ws.send(s);
}

function handleAuth(ws, msg) {
  const user = String(msg.user || '').trim();
  const pass = String(msg.pass || '');
  const key = user.toLowerCase();
  const fail = err => send(ws, { type: 'auth', ok: false, err });

  if (!/^[a-z0-9_]{3,16}$/.test(key)) return fail('Usuário: 3–16 letras, números ou _.');
  if (pass.length < 4 || pass.length > 64) return fail('Senha: entre 4 e 64 caracteres.');

  if (msg.type === 'register') {
    if (accounts[key]) return fail('Esse nome já existe.');
    const salt = crypto.randomBytes(16).toString('hex');
    accounts[key] = { salt, hash: hashPass(pass, salt) };
    saveAccounts();
  } else {
    const acc = accounts[key];
    if (!acc || !checkPass(acc, pass)) return fail('Nome ou senha incorretos.');
  }

  for (const other of byWs.values()) {
    if (other.key === key && other.ws !== ws) return fail('Essa conta já está jogando.');
  }

  // se esse socket já estava logado, tira o jogador antigo
  const old = byWs.get(ws);
  if (old) { byWs.delete(ws); byId.delete(old.id); }

  const p = {
    ws, id: nextId++, key, name: user, admin: key === ADMIN_KEY,
    x: 0, y: 0, z: 0, yaw: 0, hp: MAX_HP, w: 'rifle',
    kills: 0, deaths: 0, pd: false, away: true,
  };
  byWs.set(ws, p);
  byId.set(p.id, p);
  send(ws, { type: 'auth', ok: true, user: p.name, admin: p.admin, id: p.id });
  broadcast({ type: 'notice', text: `${p.name} entrou` }, ws);
}

// arma PD: apaga a conta do jogador atingido, avisa todos e desconecta
function apagarPorPd(vic) {
  broadcast({ type: 'notice', text: `O jogador ${vic.name} foi atingido pela dourada por infringir regras` });
  delete accounts[vic.key];
  saveAccounts();
  send(vic.ws, { type: 'deleted', reason: 'Você foi atingido pela arma PD por infringir regras. Sua conta foi apagada.' });
  byWs.delete(vic.ws);
  byId.delete(vic.id);
  try { vic.ws.close(); } catch (e) { /* ok */ }
}

function applyDamage(att, vic, dmg, pd) {
  vic.hp = Math.max(0, vic.hp - dmg);
  send(vic.ws, { type: 'damage', hp: vic.hp });
  if (vic.hp <= 0) {
    att.kills++;
    vic.deaths++;
    broadcast({ type: 'kill', killer: att.name, victim: vic.name, kid: att.id, pd });
    send(att.ws, { type: 'kill', killer: att.name, victim: vic.name, kid: att.id, pd });
  }
}

function onMessage(ws, raw) {
  let msg;
  try { msg = JSON.parse(raw); } catch (e) { return; }
  if (msg.type === 'login' || msg.type === 'register') return handleAuth(ws, msg);

  const p = byWs.get(ws);
  if (!p) return;   // sem login, ignora tudo

  switch (msg.type) {
    case 'state': {
      p.x = num(msg.x); p.y = num(msg.y); p.z = num(msg.z); p.yaw = num(msg.yaw);
      if (typeof msg.w === 'string') p.w = msg.w;
      if (Number.isFinite(msg.hp)) {
        const hp = clamp(msg.hp, 0, MAX_HP);
        // aceita HP menor (cliente tomou dano) ou volta a 100 só se já estava morto (respawn)
        if (hp <= p.hp || p.hp <= 0) p.hp = hp;
      }
      return;
    }
    case 'shot': {
      if (!vec3(msg.origin) || !vec3(msg.end)) return;
      broadcast({ type: 'shot', origin: msg.origin, end: msg.end, w: p.w }, ws);
      return;
    }
    case 'hit': {
      const t = byId.get(msg.target);
      const dmg = clamp(num(msg.dmg), 0, MAX_HP);
      if (!t || t === p || t.away || t.hp <= 0) return;
      applyDamage(p, t, dmg, false);
      return;
    }
    case 'pdhit': {
      if (!p.admin || !p.pd) return;
      const t = byId.get(msg.target);
      if (!t || t === p || t.away) return;
      apagarPorPd(t);
      return;
    }
    case 'pd': {
      p.pd = p.admin && !!msg.on;   // só a conta dona liga a arma PD
      send(ws, { type: 'pd', on: p.pd });
      return;
    }
    case 'away': {
      p.away = !!msg.on;
      return;
    }
  }
}

// ---------- envio periódico da lista de jogadores ----------
setInterval(() => {
  for (const [ws, me] of byWs) {
    if (ws.readyState !== 1 || me.away) continue;
    const players = [];
    for (const other of byWs.values()) {
      if (other === me || other.away) continue;
      players.push({
        id: other.id, name: other.name, admin: other.admin,
        x: other.x, y: other.y, z: other.z, yaw: other.yaw,
        dead: other.hp <= 0, w: other.w,
      });
    }
    send(ws, { type: 'players', players, kills: me.kills, deaths: me.deaths });
  }
}, TICK_MS);

// ---------- HTTP (também responde o health check do Render) + WebSocket ----------
const server = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end('FPS Base: servidor online');
});

const wss = new WebSocketServer({ server, maxPayload: 16 * 1024 });
wss.on('connection', ws => {
  ws.on('message', raw => onMessage(ws, raw));
  ws.on('close', () => {
    const p = byWs.get(ws);
    if (!p) return;
    byWs.delete(ws);
    byId.delete(p.id);
    broadcast({ type: 'notice', text: `${p.name} saiu` });
  });
  ws.on('error', () => {});
});

server.listen(PORT, () => console.log(`Servidor FPS na porta ${PORT}`));
