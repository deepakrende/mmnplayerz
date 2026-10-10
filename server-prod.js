// IPTV Player: production server (Node 18+). Serves the player and a hardened stream proxy.
// Env: PORT, ADMIN_PASSWORD (turns on /admin to manage member access codes), DATA_DIR (Render Disk mount path where members are saved), SESSION_SECRET, ACCESS_CODES (optional first import), ACCESS_PASSWORD (old single password, only used when there is no admin and no members), TRUST_PROXY=1 (Caddy/nginx) or render, RATE_LIMIT, MAX_STREAMS_PER_IP, ALLOW_INSECURE_TLS=1
const http = require('http'), https = require('https'), fs = require('fs'), path = require('path');
const dns = require('dns'), net = require('net'), crypto = require('crypto');

const PORT = +process.env.PORT || 8787;
const PASS = process.env.ACCESS_PASSWORD || '';
const TRUST_MODE = process.env.TRUST_PROXY || '';   // '1' = Caddy/nginx, 'render' = Render
const TRUST = TRUST_MODE === '1';
const RATE = +process.env.RATE_LIMIT || 900;            // proxy requests per minute per IP
const MAX_CONC = +process.env.MAX_STREAMS_PER_IP || 8;  // simultaneous open streams per IP
const INSECURE = process.env.ALLOW_INSECURE_TLS === '1';
const MAX_PLAYLIST = 80 * 1024 * 1024;
const UA = 'VLC/3.0.18 LibVLC/3.0.18';
const agents = { 'http:': new http.Agent({ keepAlive: true, maxSockets: 200 }), 'https:': new https.Agent({ keepAlive: true, maxSockets: 200 }) };
const px = u => '/proxy?u=' + encodeURIComponent(u);

const CSP = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; " +
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src * data:; media-src 'self' blob:; connect-src 'self'; worker-src 'self' blob:; " +
  "frame-ancestors 'none'; base-uri 'none'";
const SEC = { 'Content-Security-Policy': CSP, 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY' };

/* ---- block requests to private / internal addresses (SSRF protection) ---- */
function isPrivate(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || a >= 224;
  }
  const x = ip.toLowerCase();
  if (x === '::1' || x === '::') return true;
  if (x.startsWith('::ffff:')) { const v4 = x.slice(7); return net.isIPv4(v4) ? isPrivate(v4) : true; }
  return /^f[cd]/.test(x) || /^fe[89ab]/.test(x);
}
// Checked at connection time, so DNS rebinding cannot swap in an internal address.
function safeLookup(host, opts, cb) {
  dns.lookup(host, { ...opts, all: true }, (err, addrs) => {
    if (err) return cb(err);
    const ok = addrs.filter(a => !isPrivate(a.address));
    if (!ok.length) return cb(new Error('Blocked address'));
    if (opts.all) return cb(null, ok);
    cb(null, ok[0].address, ok[0].family);
  });
}
function upstream(target, headers, signal, hops = 0) {
  return new Promise((resolve, reject) => {
    let u; try { u = new URL(target); } catch { return reject(new Error('Bad url')); }
    if (!/^https?:$/.test(u.protocol)) return reject(new Error('Bad url'));
    const host = u.hostname.replace(/^\[|\]$/g, '');
    if (net.isIP(host) && isPrivate(host)) return reject(new Error('Blocked address'));
    const lib = u.protocol === 'https:' ? https : http;
    const req = lib.request(u, { method: 'GET', headers, lookup: safeLookup, timeout: 30000, agent: agents[u.protocol], rejectUnauthorized: !INSECURE }, res => {
      if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
        res.resume();
        if (hops >= 5) return reject(new Error('Too many redirects'));
        return resolve(upstream(new URL(res.headers.location, u).href, headers, signal, hops + 1));
      }
      res.finalUrl = u.href; resolve(res);
    });
    req.on('timeout', () => req.destroy(new Error('Upstream timeout')));
    req.on('error', reject);
    if (signal.aborted) req.destroy();
    else { const onAbort = () => req.destroy(); signal.addEventListener('abort', onAbort, { once: true }); req.on('close', () => signal.removeEventListener('abort', onAbort)); }
    req.end();
  });
}

/* ---- live MPEG-TS keep-alive ----
   Some Xtream panels close a live .ts connection every ~30s. Instead of letting the browser see the
   break (and freeze while it reconnects), reconnect to the provider here and keep feeding the SAME
   response to the browser, cutting only on whole 188-byte TS packets so the stream stays valid. */
const LIVE_TS = /\/live\/[^/]+\/[^/]+\/\d+\.ts$/i;
const sleep = ms => new Promise(r => setTimeout(r, ms));
async function pumpLive(res, first, target, hd, signal, tx) {
  /* tx=true: pass the stream through ffmpeg, copying video and converting audio (AC-3/E-AC-3/MP2...) to AAC,
     because browsers cannot decode Dolby audio. Used only when the player asks for it. */
  let out = res, ff = null;
  if (tx) {
    const { spawn } = require('child_process');
    ff = spawn('ffmpeg', ['-hide_banner', '-loglevel', 'error', '-fflags', '+genpts+discardcorrupt', '-probesize', '1000000', '-analyzeduration', '1500000',
      '-i', 'pipe:0', '-map', '0:v:0?', '-map', '0:a:0?', '-c:v', 'copy', '-c:a', 'aac', '-b:a', '128k', '-ac', '2',
      '-f', 'mpegts', '-muxdelay', '0', '-flush_packets', '1', 'pipe:1'], { stdio: ['pipe', 'pipe', 'pipe'] });
    out = ff.stdin;
    ff.stdin.on('error', () => {});
    ff.stderr.on('data', d => console.log('[ffmpeg] ' + String(d).trim().slice(0, 200)));
    ff.stdout.on('data', c => { if (!res.write(c)) { ff.stdout.pause(); res.once('drain', () => ff.stdout.resume()); } });
    ff.on('error', e => { console.log('[ffmpeg] cannot start: ' + e.message); res.end(); });
    ff.on('close', () => { if (!res.writableEnded) res.end(); });
    res.on('close', () => { try { ff.kill('SIGKILL'); } catch {} });
  }
  const host = (() => { try { return new URL(target).host; } catch { return '?'; } })();
  const headers = { ...hd }; delete headers.Range;
  let r = first, quick = 0, reconnects = 0, lastUrl = first.finalUrl, cachedOk = true, usedCached = false, lastMs = 0;
  for (;;) {
    const t0 = Date.now(); let got = 0, carry = Buffer.alloc(0), why = 'end';
    await new Promise(resolve => {
      r.on('data', c => {
        got += c.length;
        const buf = carry.length ? Buffer.concat([carry, c]) : c;
        const n = buf.length - (buf.length % 188);
        carry = buf.subarray(n);
        if (n && !out.write(buf.subarray(0, n))) { r.pause(); out.once('drain', () => r.resume()); }
      });
      r.on('end', resolve);
      r.on('error', e => { why = 'error: ' + e.message; resolve(); });
      r.on('close', () => { if (why === 'end') why = 'close'; resolve(); });
    });
    if (signal.aborted || res.destroyed) return;
    const secs = Math.round((Date.now() - t0) / 100) / 10;
    console.log('[live] provider ended stream host=' + host + ' after ' + secs + 's, ' + got + ' bytes (' + why + '); last reconnect took ' + lastMs + 'ms; reconnect #' + (reconnects + 1));
    if (got < 188 * 20 || secs < 3) { quick++; if (usedCached) cachedOk = false; } else quick = 0;
    if (quick >= 4 || ++reconnects > 2000) break;
    if (quick) await sleep(400 * quick);
    if (signal.aborted || res.destroyed) return;
    const tc = Date.now();
    try {
      usedCached = false;
      if (cachedOk && lastUrl) {
        try { r = await upstream(lastUrl, headers, signal); usedCached = true; if (r.statusCode !== 200) { r.resume(); usedCached = false; cachedOk = false; r = null; } }
        catch { cachedOk = false; r = null; }
      } else r = null;
      if (!r) r = await upstream(target, headers, signal);
      if (r.statusCode !== 200) { r.resume(); quick++; if (quick >= 4) break; r = emptyStream(); }
      else lastUrl = r.finalUrl;
    } catch (e) { quick++; if (quick >= 4) break; r = emptyStream(); }
    lastMs = Date.now() - tc;
  }
  if (ff) ff.stdin.end(); else res.end();
}
function emptyStream() { const { Readable } = require('stream'); const s = new Readable({ read() {} }); s.push(null); return s; }

function rewrite(text, base) {
  return text.split(/\r?\n/).map(l => {
    const t = l.trim();
    if (!t) return l;
    if (t[0] === '#') return l.replace(/URI="([^"]+)"/g, (m, u) => { try { return 'URI="' + px(new URL(u, base).href) + '"'; } catch { return m; } });
    try { return px(new URL(t, base).href); } catch { return l; }
  }).join('\n');
}

/* ---- limits and auth ---- */
const hits = new Map(), conc = new Map();
setInterval(() => { const n = Date.now(); for (const [k, v] of hits) if (v.reset < n) hits.delete(k); }, 60000).unref();
const clientIp = req => {
  if (TRUST_MODE === 'render') {
    const h = req.headers['true-client-ip'] || req.headers['cf-connecting-ip'];
    if (h) return String(h).trim();
    const f = (req.headers['x-forwarded-for'] || '').split(',')[0].trim();
    if (f) return f;
  }
  if (TRUST) { const x = (req.headers['x-forwarded-for'] || '').split(',').map(s => s.trim()).filter(Boolean); if (x.length) return x[x.length - 1]; }
  return req.socket.remoteAddress || '';
};
function authed(req) {
  if (!PASS) return true;
  const m = /^Basic (.+)$/.exec(req.headers.authorization || '');
  if (!m) return false;
  const given = Buffer.from(m[1], 'base64').toString().split(':').slice(1).join(':');
  const a = crypto.createHash('sha256').update(given).digest(), b = crypto.createHash('sha256').update(PASS).digest();
  return crypto.timingSafeEqual(a, b);
}
const fail = (res, code, msg) => { if (!res.headersSent) res.writeHead(code, { ...SEC, 'Content-Type': 'text/plain' }); res.end(msg); };


/* ================= Member access codes, managed from /admin =================
   Members are saved in DATA_DIR/members.json. Attach a Render Disk and set DATA_DIR to its mount path so they survive deploys.
   ADMIN_PASSWORD turns the admin page on (/admin). ACCESS_CODES is optional and only used to import a first list. */
const DATA_DIR = process.env.DATA_DIR || '';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const DEFAULT_DEVICES = +process.env.DEFAULT_DEVICES || 3;
const SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const ALPHA = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const normCode = s => String(s || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
const hashCode = code => crypto.createHash('sha256').update(normCode(code)).digest();
const fpOf = code => hashCode(code).toString('hex').slice(0, 16);
const expOf = m => m.expires == null ? Infinity : m.expires;
const newId = () => crypto.randomBytes(4).toString('hex');
function genCode() { const b = crypto.randomBytes(12); let c = ''; for (const x of b) c += ALPHA[x % ALPHA.length]; return c.slice(0, 4) + '-' + c.slice(4, 8) + '-' + c.slice(8, 12); }
function parseExpiry(x) {                       // 'YYYY-MM-DD' = through the end of that day, India time. Empty = never.
  if (!x) return null;
  if (/^\d{4}-\d{2}-\d{2}$/.test(x)) return Date.parse(x + 'T23:59:59+05:30');
  return Date.parse(x);
}
const clean = m => ({
  id: m.id || newId(), name: String(m.name || '').replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, 60), code: String(m.code || '').toUpperCase().replace(/[^A-Z0-9-]/g, ''),
  expires: m.expires == null || Number.isNaN(+m.expires) ? null : +m.expires, paused: !!m.paused,
  devices: +m.devices > 0 ? Math.floor(+m.devices) : DEFAULT_DEVICES, screens: +m.screens > 0 ? Math.floor(+m.screens) : 1,
  note: String(m.note || '').slice(0, 200), epoch: +m.epoch || 0, createdAt: +m.createdAt || Date.now()
});
function parseCodes(raw) {                      // optional first import from ACCESS_CODES: name:code:expiry[:devices[:screens]] (use | to give a time)
  const list = [];
  for (const part of String(raw || '').split(/[\n;,]+/)) {
    const t = part.trim(); if (!t) continue;
    const [name, code, exp, dev, scr] = t.split(t.includes('|') ? '|' : ':').map(x => x.trim());
    const expires = parseExpiry(exp);
    if (!name || normCode(code).length < 8 || Number.isNaN(expires)) { console.log('[access] skipped an ACCESS_CODES entry that could not be read'); continue; }
    list.push(clean({ name, code, expires, devices: dev, screens: scr }));
  }
  return list;
}

let STORE = { members: [], usage: {} };
const storeInfo = { persistent: false, mounted: false, dir: DATA_DIR, error: '' };
const STORE_FILE = DATA_DIR ? path.join(DATA_DIR, 'members.json') : '';
let BYFP = new Map(), HASHES = [], usageDirty = false;
const DEVICES = new Map();   // fp -> Map(deviceId -> lastSeen)
const STREAMS = new Map();   // fp -> Map(deviceId -> open stream count)
const OPEN = new Map();      // fp -> Set(open response objects), so a stream can be cut when access ends
const tries = new Map(), atries = new Map();   // wrong-password attempts per IP
function rebuild() {
  BYFP = new Map(); HASHES = [];
  for (const m of STORE.members) { m.fp = fpOf(m.code); BYFP.set(m.fp, m); HASHES.push({ hash: hashCode(m.code), m }); }
}
function saveStore() {
  if (!storeInfo.persistent) return false;
  try {
    const cut = istDay(Date.now() - 120 * 86400000);
    for (const id of Object.keys(STORE.usage)) { for (const d of Object.keys(STORE.usage[id])) if (d < cut) delete STORE.usage[id][d]; }
    const data = { version: 1, members: STORE.members.map(m => clean(m)), usage: STORE.usage };
    fs.writeFileSync(STORE_FILE + '.tmp', JSON.stringify(data)); fs.renameSync(STORE_FILE + '.tmp', STORE_FILE);
    usageDirty = false; storeInfo.error = ''; return true;
  } catch (e) { storeInfo.error = e.message; console.log('[admin] could not save members: ' + e.message); return false; }
}
function loadStore() {
  if (DATA_DIR) {
    try {
      fs.mkdirSync(DATA_DIR, { recursive: true }); fs.accessSync(DATA_DIR, fs.constants.W_OK);
      storeInfo.persistent = true;
      try { storeInfo.mounted = fs.statSync(DATA_DIR).dev !== fs.statSync('/').dev; } catch {}
      if (fs.existsSync(STORE_FILE)) {
        const j = JSON.parse(fs.readFileSync(STORE_FILE, 'utf8'));
        STORE = { members: (j.members || []).map(clean).filter(m => m.name && normCode(m.code).length >= 8), usage: j.usage || {} };
        rebuild(); return;
      }
    } catch (e) { storeInfo.persistent = false; storeInfo.error = e.message; console.log('[admin] cannot use DATA_DIR (' + DATA_DIR + '): ' + e.message); }
  }
  STORE = { members: parseCodes(process.env.ACCESS_CODES), usage: {} };
  rebuild(); if (storeInfo.persistent && STORE.members.length) saveStore();
}
const istDay = (t = Date.now()) => new Date(t).toLocaleDateString('en-CA', { timeZone: 'Asia/Kolkata' });
function addUsage(m, mb) { if (!(mb > 0)) return; const d = istDay(), u = STORE.usage[m.id] || (STORE.usage[m.id] = {}); u[d] = Math.round(((u[d] || 0) + mb) * 10) / 10; usageDirty = true; }
function usageOf(m) {
  const u = STORE.usage[m.id] || {}, today = istDay(), mon = today.slice(0, 7); let t = 0, mo = 0, tot = 0;
  for (const [d, v] of Object.entries(u)) { tot += v; if (d === today) t += v; if (d.startsWith(mon)) mo += v; }
  return { today: Math.round(t), month: Math.round(mo), total: Math.round(tot) };
}
const gateOn = () => !!ADMIN_PASSWORD || STORE.members.length > 0;
const dateStr = ms => ms === Infinity || ms == null ? 'never' : new Date(ms).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'Asia/Kolkata' });
function killMember(fp) { const set = OPEN.get(fp); if (set) for (const r of [...set]) { try { r.destroy(); } catch {} } }
setInterval(() => {            // cut running streams when access ends (expiry, pause, removal)
  for (const fp of OPEN.keys()) { const m = BYFP.get(fp); if (!m || m.paused || Date.now() > expOf(m)) killMember(fp); }
  if (usageDirty) saveStore();
}, 20000).unref();
process.on('SIGTERM', () => { try { saveStore(); } catch {} process.exit(0); });

const sign = obj => { const body = Buffer.from(JSON.stringify(obj)).toString('base64url'); return body + '.' + crypto.createHmac('sha256', SECRET).update(body).digest('base64url'); };
function verify(tok) {
  const i = (tok || '').lastIndexOf('.'); if (i < 1) return null;
  const body = tok.slice(0, i), mac = tok.slice(i + 1), exp = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  if (mac.length !== exp.length || !crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(exp))) return null;
  try { return JSON.parse(Buffer.from(body, 'base64url').toString()); } catch { return null; }
}
const cookieOf = (req, name) => { for (const p of (req.headers.cookie || '').split(';')) { const i = p.indexOf('='); if (i > 0 && p.slice(0, i).trim() === name) return decodeURIComponent(p.slice(i + 1).trim()); } return ''; };
const isHttps = req => req.headers['x-forwarded-proto'] === 'https' || !!req.socket.encrypted;
const setCookie = (req, name, val, maxAgeSec, p = '/', strict = false) => name + '=' + encodeURIComponent(val) + '; Path=' + p + '; HttpOnly; SameSite=' + (strict ? 'Strict' : 'Lax') + '; Max-Age=' + maxAgeSec + (isHttps(req) ? '; Secure' : '');
function pruneDevices(devs) { const cut = Date.now() - 14 * 86400000; for (const [d, t] of devs) if (t < cut) devs.delete(d); }

/* returns { entry, device } for a signed-in member, or { error } */
function memberOf(req) {
  const p = verify(cookieOf(req, 'mmn_session'));
  if (!p) return { error: 'login' };
  const e = BYFP.get(p.f);
  if (!e) return { error: 'revoked' };
  if (e.paused) return { error: 'paused', entry: e };
  if (Date.now() > expOf(e)) return { error: 'expired', entry: e };
  if ((p.e | 0) !== (e.epoch | 0)) return { error: 'signedout', entry: e };
  let devs = DEVICES.get(e.fp); if (!devs) DEVICES.set(e.fp, devs = new Map());
  if (!devs.has(p.d)) { pruneDevices(devs); if (devs.size >= e.devices) return { error: 'devices', entry: e }; }
  devs.set(p.d, Date.now());
  return { entry: e, device: p.d };
}
function streamInc(w, res) { let m = STREAMS.get(w.entry.fp); if (!m) STREAMS.set(w.entry.fp, m = new Map()); m.set(w.device, (m.get(w.device) || 0) + 1); let o = OPEN.get(w.entry.fp); if (!o) OPEN.set(w.entry.fp, o = new Set()); o.add(res); }
function streamDec(w, res) { const m = STREAMS.get(w.entry.fp); if (m) { const n = (m.get(w.device) || 1) - 1; n ? m.set(w.device, n) : m.delete(w.device); } const o = OPEN.get(w.entry.fp); if (o) { o.delete(res); if (!o.size) OPEN.delete(w.entry.fp); } }
function otherScreens(w) { const m = STREAMS.get(w.entry.fp); let n = 0; if (m) for (const [d, c] of m) if (d !== w.device && c > 0) n++; return n; }

const WHY = {
  expired: 'Your access code has expired. Enter a new code to continue.',
  revoked: 'Your access was removed. Enter a new code to continue.',
  paused: 'Your access is paused. Please contact the owner.',
  signedout: 'You were signed out. Enter your code to continue.',
  devices: 'This code is already signed in on the maximum number of devices.'
};
function gatePage(why) {
  const note = WHY[why] || '';
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>MMN · Access</title>
<style>:root{--bg:#0d0f1f;--panel:#161938;--line:#2a2e5c;--text:#eef0ff;--mute:#9aa0d0;--accent:#8b7bff;--err:#ff7a8a}*{box-sizing:border-box}html,body{height:100%;margin:0}
body{background:var(--bg);color:var(--text);font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;display:grid;place-items:center;padding:24px}
main{width:100%;max-width:420px}.logo{display:flex;align-items:center;gap:12px;margin-bottom:26px}.logo i{width:40px;height:40px;border-radius:12px;background:var(--accent);display:grid;place-items:center}
.logo i:after{content:"";border-left:13px solid #fff;border-top:8px solid transparent;border-bottom:8px solid transparent;margin-left:3px}.logo b{font-size:28px}
h1{font-size:22px;margin:0 0 6px}p{color:var(--mute);margin:0 0 18px}input{width:100%;padding:14px 16px;border-radius:12px;border:1px solid var(--line);background:var(--panel);color:var(--text);font:600 18px ui-monospace,Consolas,monospace;letter-spacing:2px;text-transform:uppercase}
input:focus{outline:2px solid var(--accent);outline-offset:2px}button{margin-top:12px;width:100%;padding:14px;border:0;border-radius:12px;background:var(--accent);color:#fff;font:600 16px inherit;cursor:pointer}button:disabled{opacity:.6;cursor:default}
#msg{min-height:1.5em;margin-top:14px;color:var(--err);font-size:14px}small{display:block;margin-top:22px;color:var(--mute)}</style></head><body><main>
<div class="logo"><i></i><b>MMN</b></div><h1>Enter your access code</h1><p>Access is by invitation. Ask the person who invited you for a code.</p>
<form id="f"><input id="c" autocomplete="off" autocapitalize="characters" spellcheck="false" maxlength="40" placeholder="XXXX-XXXX-XXXX" aria-label="Access code" autofocus><button id="b" type="submit">Continue</button></form>
<div id="msg" role="alert">${note}</div><small>Your code is private. Do not share it.</small></main>
<script>const f=document.getElementById('f'),c=document.getElementById('c'),b=document.getElementById('b'),m=document.getElementById('msg');
f.onsubmit=async e=>{e.preventDefault();if(!c.value.trim())return;b.disabled=true;m.textContent='';
try{const r=await fetch('/gate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code:c.value})});const j=await r.json().catch(()=>({}));
if(r.ok){location.href='/app';return}m.textContent=j.error||'Could not check the code. Try again.'}catch(x){m.textContent='Could not reach the server. Try again.'}b.disabled=false};</script></body></html>`;
}
function readBody(req, max = 8192) {
  return new Promise((resolve, reject) => {
    let n = 0; const ch = [];
    req.on('data', c => { n += c.length; if (n > max) { reject(new Error('too big')); req.destroy(); return; } ch.push(c); });
    req.on('end', () => resolve(Buffer.concat(ch).toString())); req.on('error', reject);
  });
}
const sendJson = (res, code, o, extra) => { res.writeHead(code, { ...SEC, 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...(extra || {}) }); res.end(JSON.stringify(o)); };

async function handleGate(req, res, u) {
  if (!gateOn()) { res.writeHead(302, { Location: '/app' }); return res.end(); }
  if (req.method === 'GET') {
    if (!memberOf(req).error && !u.searchParams.get('why')) { res.writeHead(302, { Location: '/app' }); return res.end(); }
    res.writeHead(200, { ...SEC, 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    return res.end(gatePage(u.searchParams.get('why') || ''));
  }
  if (req.method !== 'POST') return fail(res, 405, 'GET or POST only');
  const site = req.headers['sec-fetch-site']; if (site && site !== 'same-origin') return fail(res, 403, 'Same-origin requests only');
  const ip = clientIp(req), now = Date.now();
  let t = tries.get(ip); if (!t || t.reset < now) { t = { n: 0, reset: now + 15 * 60000 }; tries.set(ip, t); }
  if (t.n >= 10) return sendJson(res, 429, { error: 'Too many wrong attempts. Please try again in a few minutes.' });
  let code = '';
  try { const raw = await readBody(req); try { code = JSON.parse(raw).code; } catch { code = new URLSearchParams(raw).get('code'); } } catch { return sendJson(res, 400, { error: 'Bad request' }); }
  const h = hashCode(code);
  let found = null; for (const x of HASHES) if (crypto.timingSafeEqual(h, x.hash)) found = x.m;   // checks every code, so timing reveals nothing
  if (!found || !normCode(code)) { t.n++; console.log('[access] wrong code from ' + ip); return sendJson(res, 401, { error: 'That code is not valid.' }); }
  if (found.paused) return sendJson(res, 401, { error: WHY.paused });
  if (Date.now() > expOf(found)) return sendJson(res, 401, { error: 'This code expired on ' + dateStr(found.expires) + '.' });
  let devs = DEVICES.get(found.fp); if (!devs) DEVICES.set(found.fp, devs = new Map());
  pruneDevices(devs);
  const old = verify(cookieOf(req, 'mmn_session'));
  let device = old && old.f === found.fp && (old.e | 0) === (found.epoch | 0) && devs.has(old.d) ? old.d : null;   // same browser signing in again keeps its slot
  if (!device) {
    if (devs.size >= found.devices) { console.log('[access] ' + found.name + ' refused: device limit (' + found.devices + ')'); return sendJson(res, 401, { error: 'This code is already signed in on ' + found.devices + ' device' + (found.devices > 1 ? 's' : '') + '. Ask the owner to reset it.' }); }
    device = crypto.randomBytes(8).toString('hex');
  }
  devs.set(device, Date.now());
  const ttl = Math.max(60, Math.min(30 * 86400, Math.floor((expOf(found) - Date.now()) / 1000)));
  console.log('[access] sign-in ok member=' + found.name + ' device=' + device.slice(0, 4) + ' (' + devs.size + '/' + found.devices + ' devices)');
  return sendJson(res, 200, { ok: true }, { 'Set-Cookie': setCookie(req, 'mmn_session', sign({ f: found.fp, d: device, e: found.epoch | 0 }), ttl) });
}

/* ---------- admin ---------- */
const adminHash = ADMIN_PASSWORD ? crypto.createHash('sha256').update(ADMIN_PASSWORD).digest() : null;
const adminOk = req => { const p = verify(cookieOf(req, 'mmn_admin')); return !!(p && p.a === 1 && p.x > Date.now()); };
function memberView(m) {
  const devs = DEVICES.get(m.fp); if (devs) pruneDevices(devs);
  const st = STREAMS.get(m.fp); let watching = 0; if (st) for (const c of st.values()) if (c > 0) watching++;
  let last = 0; if (devs) for (const t of devs.values()) last = Math.max(last, t);
  return { id: m.id, name: m.name, code: m.code, expires: m.expires, expiresDate: m.expires == null ? '' : istDay(m.expires), paused: m.paused, devices: m.devices, screens: m.screens, note: m.note,
    createdAt: m.createdAt, devicesUsed: devs ? devs.size : 0, watching, lastSeen: last || null, usage: usageOf(m) };
}
function applyFields(m, b) {
  if ('name' in b) { const n = String(b.name || '').replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, 60); if (!n) throw new Error('Please enter a name'); m.name = n; }
  if ('expires' in b) { if (b.expires === '' || b.expires == null) m.expires = null; else { const t = parseExpiry(String(b.expires)); if (Number.isNaN(t)) throw new Error('Cannot read that date'); m.expires = t; } }
  if ('devices' in b) { const d = +b.devices; if (!(d >= 1 && d <= 20)) throw new Error('Devices must be between 1 and 20'); m.devices = Math.floor(d); }
  if ('screens' in b) { const d = +b.screens; if (!(d >= 1 && d <= 10)) throw new Error('"At once" must be between 1 and 10'); m.screens = Math.floor(d); }
  if ('paused' in b) m.paused = !!b.paused;
  if ('note' in b) m.note = String(b.note || '').slice(0, 200);
  if ('code' in b && String(b.code || '').trim()) {
    const c = String(b.code).toUpperCase().replace(/[^A-Z0-9-]/g, ''), n = normCode(c);
    if (n.length < 8 || n.length > 32) throw new Error('A code needs 8 to 32 letters or numbers');
    if (STORE.members.some(x => x !== m && normCode(x.code) === n)) throw new Error('Another member already has that code');
    m.code = c;
  }
}
function dropSessions(fp) { DEVICES.delete(fp); killMember(fp); }
async function handleAdmin(req, res, u) {
  if (!adminHash) return fail(res, 404, 'Admin is off. Set ADMIN_PASSWORD to turn it on.');
  const p = u.pathname;
  if (p === '/admin' || p === '/admin/') {
    if (req.method !== 'GET') return fail(res, 405, 'GET only');
    let html; try { html = fs.readFileSync(path.join(__dirname, 'admin.html')); } catch { return fail(res, 500, 'admin.html is missing from the server files'); }
    res.writeHead(200, { ...SEC, 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' }); return res.end(html);
  }
  const site = req.headers['sec-fetch-site'];
  if (req.method !== 'GET' && ((site && site !== 'same-origin') || req.headers['x-admin'] !== '1')) return fail(res, 403, 'Not allowed');
  if (p === '/admin/login' && req.method === 'POST') {
    const ip = clientIp(req), now = Date.now();
    let t = atries.get(ip); if (!t || t.reset < now) { t = { n: 0, reset: now + 15 * 60000 }; atries.set(ip, t); }
    if (t.n >= 5) return sendJson(res, 429, { error: 'Too many wrong attempts. Try again in a few minutes.' });
    let pw = ''; try { pw = JSON.parse(await readBody(req)).password || ''; } catch { return sendJson(res, 400, { error: 'Bad request' }); }
    if (!crypto.timingSafeEqual(crypto.createHash('sha256').update(String(pw)).digest(), adminHash)) { t.n++; console.log('[admin] wrong password from ' + ip); return sendJson(res, 401, { error: 'Wrong password.' }); }
    console.log('[admin] login from ' + ip);
    return sendJson(res, 200, { ok: true }, { 'Set-Cookie': setCookie(req, 'mmn_admin', sign({ a: 1, x: Date.now() + 12 * 3600000 }), 12 * 3600, '/admin', true) });
  }
  if (p === '/admin/logout') return sendJson(res, 200, { ok: true }, { 'Set-Cookie': setCookie(req, 'mmn_admin', '', 0, '/admin', true) });
  if (!adminOk(req)) return sendJson(res, 401, { error: 'login' });
  try {
    if (p === '/admin/api/state' && req.method === 'GET') {
      return sendJson(res, 200, { now: Date.now(), storage: { persistent: storeInfo.persistent, mounted: storeInfo.mounted, error: storeInfo.error, dir: storeInfo.dir, wantsDisk: !DATA_DIR }, members: STORE.members.map(memberView) });
    }
    if (p === '/admin/api/members' && req.method === 'POST') {
      const b = JSON.parse(await readBody(req) || '{}');
      if (STORE.members.length >= 500) throw new Error('Member limit reached (500)');
      const m = clean({ name: 'x', code: genCode(), devices: DEFAULT_DEVICES, screens: 1 }); m.name = '';
      applyFields(m, { devices: DEFAULT_DEVICES, screens: 1, ...b });
      if (!m.name) throw new Error('Please enter a name');
      STORE.members.push(m); rebuild(); const saved = saveStore();
      console.log('[admin] added member ' + m.name);
      return sendJson(res, 200, { ok: true, saved, member: memberView(m) });
    }
    const mm = /^\/admin\/api\/members\/([a-f0-9]{8})(?:\/(newcode|signout))?$/.exec(p);
    if (mm) {
      const m = STORE.members.find(x => x.id === mm[1]); if (!m) return sendJson(res, 404, { error: 'Member not found' });
      const act = mm[2], oldFp = m.fp;
      if (req.method === 'DELETE' && !act) {
        dropSessions(m.fp); STORE.members = STORE.members.filter(x => x !== m); delete STORE.usage[m.id]; rebuild(); const saved = saveStore();
        console.log('[admin] removed member ' + m.name); return sendJson(res, 200, { ok: true, saved });
      }
      if (req.method === 'POST' && act === 'newcode') {
        m.code = genCode(); dropSessions(oldFp); m.epoch++; rebuild(); const saved = saveStore();
        console.log('[admin] new code for ' + m.name); return sendJson(res, 200, { ok: true, saved, member: memberView(m) });
      }
      if (req.method === 'POST' && act === 'signout') {
        m.epoch++; dropSessions(m.fp); const saved = saveStore();
        console.log('[admin] signed out all devices of ' + m.name); return sendJson(res, 200, { ok: true, saved, member: memberView(m) });
      }
      if (req.method === 'PUT' && !act) {
        const b = JSON.parse(await readBody(req) || '{}'), before = { code: m.code, paused: m.paused, expires: m.expires };
        applyFields(m, b);
        if (m.code !== before.code) { dropSessions(oldFp); m.epoch++; }
        rebuild(); if ((m.paused && !before.paused) || (expOf(m) < Date.now())) killMember(m.fp);
        const saved = saveStore(); console.log('[admin] updated member ' + m.name);
        return sendJson(res, 200, { ok: true, saved, member: memberView(m) });
      }
    }
    return sendJson(res, 404, { error: 'Not found' });
  } catch (e) { return sendJson(res, 400, { error: e.message || 'Bad request' }); }
}
loadStore();
console.log('[access] ' + (gateOn() ? 'access codes are ON: ' + STORE.members.length + ' member(s)' : 'access codes are OFF (no ADMIN_PASSWORD and no members)'));
if (ADMIN_PASSWORD) console.log('[admin] admin page is ON at /admin · saved on disk: ' + (storeInfo.persistent ? 'yes' + (storeInfo.mounted ? '' : ' (WARNING: ' + DATA_DIR + ' does not look like a separate disk, so it may be wiped on deploy)') : 'NO, members will be lost on restart. Attach a Render Disk and set DATA_DIR'));
if (gateOn() && !process.env.SESSION_SECRET) console.log('[access] WARNING: SESSION_SECRET is not set, so everyone is signed out whenever the server restarts.');

const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, 'http://localhost');
  if (u.pathname === '/healthz') return fail(res, 200, 'ok');
  if (u.pathname === '/' || u.pathname === '/index.html') {
    try {
      res.writeHead(200, { ...SEC, 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache' });
      return res.end(fs.readFileSync(path.join(__dirname, 'landing.html')));
    } catch { return fail(res, 500, 'landing.html not found'); }
  }
  if (u.pathname === '/admin' || u.pathname.startsWith('/admin/')) return handleAdmin(req, res, u);
  if (u.pathname === '/gate') return handleGate(req, res, u);
  if (u.pathname === '/logout') { res.writeHead(302, { Location: '/gate', 'Set-Cookie': setCookie(req, 'mmn_session', '', 0), 'Cache-Control': 'no-store' }); return res.end(); }
  let who = null;
  if (gateOn()) {
    if (u.pathname === '/app' || u.pathname === '/proxy' || u.pathname === '/diag' || u.pathname === '/session') {
      const m = memberOf(req);
      if (m.error) {
        if (u.pathname === '/app') { res.writeHead(302, { Location: m.error === 'login' ? '/gate' : '/gate?why=' + m.error, 'Cache-Control': 'no-store' }); return res.end(); }
        res.writeHead(401, { ...SEC, 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
        return res.end(JSON.stringify({ error: m.error }));
      }
      who = m;
    }
  } else if (!authed(req)) { res.writeHead(401, { ...SEC, 'WWW-Authenticate': 'Basic realm="IPTV Player"' }); return res.end('Password required'); }
  if (u.pathname === '/session') {
    res.writeHead(200, { ...SEC, 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
    return res.end(JSON.stringify(who ? { name: who.entry.name, expires: expOf(who.entry) === Infinity ? null : expOf(who.entry) } : { name: '', expires: null }));
  }

  if (u.pathname === '/proxy' || u.pathname === '/diag') {
    if (req.method !== 'GET') return fail(res, 405, 'GET only');
    req.socket.setNoDelay(true);
    const site = req.headers['sec-fetch-site'];
    if (site && site !== 'same-origin') return fail(res, 403, 'Same-origin requests only');
    const ip = clientIp(req), now = Date.now();
    let h = hits.get(ip); if (!h || h.reset < now) { h = { n: 0, reset: now + 60000 }; hits.set(ip, h); }
    if (++h.n > RATE) return fail(res, 429, 'Too many requests');
    if ((conc.get(ip) || 0) >= MAX_CONC) return fail(res, 429, 'Too many open streams');
    if (who && otherScreens(who) >= who.entry.screens) return fail(res, 429, 'This access code is already in use on another device');
    const target = u.searchParams.get('u') || '';
    const ac = new AbortController();
    conc.set(ip, (conc.get(ip) || 0) + 1);
    if (who) streamInc(who, res);
    const b0 = req.socket.bytesWritten;
    let done = false;
    const release = () => { if (!done) { done = true; const c = (conc.get(ip) || 1) - 1; c ? conc.set(ip, c) : conc.delete(ip); if (who) { streamDec(who, res); const mb = (req.socket.bytesWritten - b0) / 1e6; addUsage(who.entry, mb); if (mb >= 1) console.log('[usage] member=' + who.entry.name + ' MB=' + mb.toFixed(1)); } } };
    res.on('close', () => { ac.abort(); release(); });
    try {
      const hd = { 'User-Agent': UA, Accept: '*/*' };
      if (req.headers.range) hd.Range = req.headers.range;
      const r = await upstream(target, hd, ac.signal);
      if (u.pathname === '/diag') {
        const chunks = []; let n = 0;
        await new Promise(done => {
          r.on('data', c => { chunks.push(c); n += c.length; if (n >= 512) { r.destroy(); done(); } });
          r.on('end', done); r.on('close', done); r.on('error', done);
          setTimeout(done, 8000);
        });
        const b = Buffer.concat(chunks), head = b.slice(0, 20).toString('latin1');
        const kind = b[0] === 0x47 ? 'MPEG-TS video' : head.startsWith('#EXTM3U') ? 'HLS/M3U playlist' : head.startsWith('FLV') ? 'FLV video'
          : b.slice(4, 8).toString() === 'ftyp' ? 'MP4 video' : /^\s*</.test(head) ? 'HTML/XML page' : b.length ? 'unknown data' : 'empty';
        const mask = x => x.replace(/(live|movie|series)\/[^\/\s]+\/[^\/\s]+\//g, '$1/***/***/');
        const snippet = /HTML|M3U|unknown/.test(kind) ? mask(b.toString('utf8', 0, 200)) : '';
        res.writeHead(200, { ...SEC, 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
        return res.end(JSON.stringify({ status: r.statusCode, type: r.headers['content-type'] || '', kind, bytes: b.length, host: new URL(r.finalUrl).host, redirected: r.finalUrl !== target, snippet }));
      }
      const ct = r.headers['content-type'] || '';
      const looksPlaylist = /mpegurl/i.test(ct) || /\.m3u8?$/i.test(new URL(r.finalUrl).pathname);
      if (looksPlaylist) {
        // Peek at the first bytes: a real playlist starts with #EXTM3U. Some Xtream panels answer
        // ".m3u8" with an endless MPEG-TS stream; buffering that would hang forever ("Connecting...").
        const it = r[Symbol.asyncIterator]();
        const first = await it.next();
        const head = first.done ? Buffer.alloc(0) : first.value;
        if (/^\uFEFF?\s*#EXTM3U/.test(head.toString('utf8', 0, 32))) {
          const chunks = [head]; let size = head.length;
          for (let n = await it.next(); !n.done; n = await it.next()) { size += n.value.length; if (size > MAX_PLAYLIST) { r.destroy(); return fail(res, 502, 'Playlist too large'); } chunks.push(n.value); }
          const text = Buffer.concat(chunks).toString('utf8');
          const body = text.includes('#EXT-X-') ? rewrite(text, r.finalUrl) : text;
          res.writeHead(r.statusCode, { ...SEC, 'Content-Type': ct || 'application/vnd.apple.mpegurl', 'Cache-Control': 'no-store' });
          return res.end(body);
        }
        const o = { ...SEC, 'X-Accel-Buffering': 'no', 'Cache-Control': 'no-store' };
        for (const k of ['content-type', 'content-length', 'content-range', 'accept-ranges']) if (r.headers[k]) o[k] = r.headers[k];
        res.writeHead(r.statusCode, o);
        res.write(head);
        r.on('error', () => res.end()); r.pipe(res);
        return;
      }
      const out = { ...SEC, 'X-Accel-Buffering': 'no', 'Cache-Control': 'no-store' };
      for (const k of ['content-type', 'content-length', 'content-range', 'accept-ranges']) if (r.headers[k]) out[k] = r.headers[k];
      res.writeHead(r.statusCode, out);
      let tp = ''; try { tp = new URL(target).pathname; } catch {}
      const wantTx = u.searchParams.get('tx') === '1';
      if (r.statusCode === 200 && !r.headers['content-length'] && (LIVE_TS.test(tp) || wantTx)) { pumpLive(res, r, target, hd, ac.signal, wantTx); return; }
      r.on('error', () => res.end()); r.pipe(res);
    } catch (e) { fail(res, 502, 'Proxy error: ' + e.message); }
    return;
  }

  if (u.pathname === '/app') {
    try {
      const html = fs.readFileSync(path.join(__dirname, 'iptv-player.html'), 'utf8').replace('<head>', '<head>\n<script>window.IPTV_PROXY=true</script>');
      res.writeHead(200, { ...SEC, 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache' });
      return res.end(html);
    } catch { return fail(res, 500, 'iptv-player.html not found'); }
  }
  fail(res, 404, 'Not found');
});
server.keepAliveTimeout = 65000; server.headersTimeout = 66000;
server.listen(PORT, '0.0.0.0', () => console.log('IPTV Player listening on :' + PORT + (gateOn() ? ' (access codes: ' + STORE.members.length + ')' : PASS ? ' (password protected)' : ' (NO PASSWORD OR ACCESS CODES SET)')));
