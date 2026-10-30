// IPTV Player: production server (Node 18+). Serves the player and a hardened stream proxy.
// Env: PORT, ADMIN_PASSWORD (turns on /admin to manage member access codes), DATA_DIR (Render Disk mount path where members are saved), SESSION_SECRET, ACCESS_CODES (optional first import), ACCESS_PASSWORD (old single password, only used when there is no admin and no members), TRUST_PROXY=1 (Caddy/nginx) or render, RATE_LIMIT, MAX_STREAMS_PER_IP, ALLOW_INSECURE_TLS=1
const http = require('http'), https = require('https'), fs = require('fs'), path = require('path');
const dns = require('dns'), net = require('net'), crypto = require('crypto'), zlib = require('zlib');

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

function rewrite(text, base, sfx = '') {
  return text.split(/\r?\n/).map(l => {
    const t = l.trim();
    if (!t) return l;
    if (t[0] === '#') return l.replace(/URI="([^"]+)"/g, (m, u) => { try { return 'URI="' + px(new URL(u, base).href) + sfx + '"'; } catch { return m; } });
    try { return px(new URL(t, base).href) + sfx; } catch { return l; }
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
  note: String(m.note || '').slice(0, 200), epoch: +m.epoch || 0, createdAt: +m.createdAt || Date.now(), lastSeenAt: +m.lastSeenAt || 0,
  revoked: Array.isArray(m.revoked) ? m.revoked.filter(x => /^[a-f0-9]{16}$/.test(x)).slice(-100) : []
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

let STORE = { members: [], usage: {}, daily: {}, hourly: {}, titles: {}, peak: {} };
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
    const cutD = istDay(Date.now() - 120 * 86400000), cutT = istDay(Date.now() - 45 * 86400000);
    for (const k of ['daily', 'hourly', 'peak']) for (const d of Object.keys(STORE[k])) if (d < cutD) delete STORE[k][d];
    for (const d of Object.keys(STORE.titles)) {
      if (d < cutT) { delete STORE.titles[d]; continue; }
      const ks = Object.keys(STORE.titles[d]);
      if (ks.length > 400) { ks.sort((a, b) => STORE.titles[d][b][1] - STORE.titles[d][a][1]); for (const k of ks.slice(300)) delete STORE.titles[d][k]; }
    }
    const data = { version: 1, members: STORE.members.map(m => clean(m)), usage: STORE.usage, daily: STORE.daily, hourly: STORE.hourly, titles: STORE.titles, peak: STORE.peak };
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
        STORE = { members: (j.members || []).map(clean).filter(m => m.name && normCode(m.code).length >= 8), usage: j.usage || {}, daily: j.daily || null, hourly: j.hourly || {}, titles: j.titles || {}, peak: j.peak || {} };
        if (!STORE.daily) { STORE.daily = {}; for (const u of Object.values(STORE.usage)) for (const [d, v] of Object.entries(u)) STORE.daily[d] = (STORE.daily[d] || 0) + v; }   // history from before Insights existed
        rebuild(); return;
      }
    } catch (e) { storeInfo.persistent = false; storeInfo.error = e.message; console.log('[admin] cannot use DATA_DIR (' + DATA_DIR + '): ' + e.message); }
  }
  STORE = { members: parseCodes(process.env.ACCESS_CODES), usage: {}, daily: {}, hourly: {}, titles: {}, peak: {} };
  rebuild(); if (storeInfo.persistent && STORE.members.length) saveStore();
}
const istDay = (t = Date.now()) => new Date(t).toLocaleDateString('en-CA', { timeZone: 'Asia/Kolkata' });
const r2 = x => Math.round(x * 100) / 100;
const istHour = (t = Date.now()) => new Date(t + 19800000).getUTCHours();
const METERS = new Set(), VIEWS = new Map();
function account(m, mb, meta) {
  if (!(mb > 0)) return;
  const now = Date.now(), d = istDay(now), h = istHour(now);
  const u = STORE.usage[m.id] || (STORE.usage[m.id] = {}); u[d] = r2((u[d] || 0) + mb);
  STORE.daily[d] = r2((STORE.daily[d] || 0) + mb);
  const H = STORE.hourly[d] || (STORE.hourly[d] = new Array(24).fill(0)); H[h] = r2(H[h] + mb);
  if (meta && meta.n) { const T = STORE.titles[d] || (STORE.titles[d] = {}), key = meta.k + '|' + meta.n, e = T[key] || (T[key] = [0, 0]); e[1] = r2(e[1] + mb); }
  usageDirty = true;
}
function trackView(w, meta) {          // one "view" = one device starting a title; the same title again within 30 minutes is the same view
  const key = w.entry.fp + '|' + w.device + '|' + meta.k + '|' + meta.n, now = Date.now(), last = VIEWS.get(key);
  VIEWS.set(key, now); if (last && now - last < 30 * 60000) return;
  const T = STORE.titles[istDay(now)] || (STORE.titles[istDay(now)] = {}), k2 = meta.k + '|' + meta.n, e = T[k2] || (T[k2] = [0, 0]); e[0]++; usageDirty = true;
}
setInterval(() => { for (const f of METERS) f(); }, (+process.env.METER_SECONDS || 15) * 1000).unref();
setInterval(() => { const cut = Date.now() - 3600000; for (const [k, t] of VIEWS) if (t < cut) VIEWS.delete(k); }, 600000).unref();
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
process.on('SIGTERM', () => { try { for (const f of METERS) f(); saveStore(); } catch {} process.exit(0); });

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
const DEVMETA = new Map();   // deviceId -> { label, first }
function deviceLabel(ua) {
  ua = String(ua || '');
  const os = /Windows/i.test(ua) ? 'Windows' : /Android/i.test(ua) ? 'Android' : /iPhone|iPad|iPod/i.test(ua) ? 'iPhone or iPad' : /CrOS/i.test(ua) ? 'Chromebook' : /Mac OS X|Macintosh/i.test(ua) ? 'Mac' : /Linux|X11/i.test(ua) ? 'Linux' : '';
  const tv = /SmartTV|SMART-TV|Tizen|Web0S|WebOS|HbbTV|BRAVIA|AFTT|Android TV|GoogleTV|CrKey|AppleTV/i.test(ua);
  const br = /Edg\//i.test(ua) ? 'Edge' : /OPR\/|Opera/i.test(ua) ? 'Opera' : /Firefox\//i.test(ua) ? 'Firefox' : /SamsungBrowser/i.test(ua) ? 'Samsung Internet' : /Chrome\//i.test(ua) ? 'Chrome' : /Safari\//i.test(ua) ? 'Safari' : 'Browser';
  return tv ? 'TV browser' + (os ? ' (' + os + ')' : '') : br + (os ? ' on ' + os : '');
}
function noteDevice(req, id) { if (!DEVMETA.has(id)) DEVMETA.set(id, { label: deviceLabel(req.headers['user-agent']), first: Date.now() }); }
function killDevice(fp, dev) { const set = OPEN.get(fp); if (set) for (const r of [...set]) if (r._dev === dev) { try { r.destroy(); } catch {} } }
const SAFE_NEXT = /^\/(app|me(\?pair=[A-Z2-9]{6})?|h\/[A-Za-z0-9_-]{6,40})$/;
const safeNext = p => SAFE_NEXT.test(String(p || '')) ? String(p) : '';
const gateUrl = (path, err) => '/gate?' + (err && err !== 'login' ? 'why=' + err + '&' : '') + 'next=' + encodeURIComponent(safeNext(path) || '/app');
function startSession(req, found) {      // gives this browser (or a paired TV) a device slot and a session cookie
  let devs = DEVICES.get(found.fp); if (!devs) DEVICES.set(found.fp, devs = new Map());
  pruneDevices(devs);
  const old = verify(cookieOf(req, 'mmn_session'));
  let device = old && old.f === found.fp && (old.e | 0) === (found.epoch | 0) && devs.has(old.d) && !(found.revoked || []).includes(old.d) ? old.d : null;   // same browser signing in again keeps its slot
  if (!device) {
    if (devs.size >= found.devices) return { error: 'This code is already signed in on ' + found.devices + ' device' + (found.devices > 1 ? 's' : '') + '. Remove one in My access, or ask the owner to reset it.' };
    device = crypto.randomBytes(8).toString('hex');
  }
  devs.set(device, Date.now()); noteDevice(req, device);
  const ttl = Math.max(60, Math.min(30 * 86400, Math.floor((expOf(found) - Date.now()) / 1000)));
  return { device, count: devs.size, cookie: setCookie(req, 'mmn_session', sign({ f: found.fp, d: device, e: found.epoch | 0 }), ttl) };
}
function pruneDevices(devs) { const cut = Date.now() - 14 * 86400000; for (const [d, t] of devs) if (t < cut) { devs.delete(d); DEVMETA.delete(d); } }

/* returns { entry, device } for a signed-in member, or { error } */
function memberOf(req) {
  const p = verify(cookieOf(req, 'mmn_session'));
  if (!p) return { error: 'login' };
  const e = BYFP.get(p.f);
  if (!e) return { error: 'revoked' };
  if (e.paused) return { error: 'paused', entry: e };
  if (Date.now() > expOf(e)) return { error: 'expired', entry: e };
  if ((p.e | 0) !== (e.epoch | 0)) return { error: 'signedout', entry: e };
  if (e.revoked && e.revoked.includes(p.d)) return { error: 'signedout', entry: e };
  let devs = DEVICES.get(e.fp); if (!devs) DEVICES.set(e.fp, devs = new Map());
  if (!devs.has(p.d)) { pruneDevices(devs); if (devs.size >= e.devices) return { error: 'devices', entry: e }; }
  devs.set(p.d, Date.now()); noteDevice(req, p.d);
  { const t = Date.now(); if (!e.lastSeenAt || t - e.lastSeenAt > 300000) { e.lastSeenAt = t; usageDirty = true; } }
  return { entry: e, device: p.d };
}
function streamInc(w, res) { let m = STREAMS.get(w.entry.fp); if (!m) STREAMS.set(w.entry.fp, m = new Map()); m.set(w.device, (m.get(w.device) || 0) + 1); let o = OPEN.get(w.entry.fp); if (!o) OPEN.set(w.entry.fp, o = new Set()); o.add(res); res._dev = w.device;
  let n = 0; for (const mm of STREAMS.values()) for (const c of mm.values()) if (c > 0) n++;
  const d = istDay(); if (n > (STORE.peak[d] || 0)) { STORE.peak[d] = n; usageDirty = true; } }
function streamDec(w, res) { const m = STREAMS.get(w.entry.fp); if (m) { const n = (m.get(w.device) || 1) - 1; n ? m.set(w.device, n) : m.delete(w.device); } const o = OPEN.get(w.entry.fp); if (o) { o.delete(res); if (!o.size) OPEN.delete(w.entry.fp); } }
function otherScreens(w) { const m = STREAMS.get(w.entry.fp); let n = 0; if (m) for (const [d, c] of m) if (d !== w.device && c > 0) n++; return n; }

const WHY = {
  expired: 'Your access code has expired. Enter a new code to continue.',
  revoked: 'Your access was removed. Enter a new code to continue.',
  paused: 'Your access is paused. Please contact the owner.',
  signedout: 'You were signed out. Enter your code to continue.',
  devices: 'This code is already signed in on the maximum number of devices.'
};
const GATE_HTML = String.raw`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>MMN · Access</title>
<style>:root{--bg:#0d0f1f;--panel:#161938;--line:#2a2e5c;--text:#eef0ff;--mute:#9aa0d0;--accent:#8b7bff;--err:#ff7a8a}*{box-sizing:border-box}html,body{height:100%;margin:0}
body{background:var(--bg);color:var(--text);font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;display:grid;place-items:center;padding:24px}
main{width:100%;max-width:420px}.logo{display:flex;align-items:center;gap:12px;margin-bottom:26px}.logo i{width:40px;height:40px;border-radius:12px;background:var(--accent);display:grid;place-items:center}
.logo i:after{content:"";border-left:13px solid #fff;border-top:8px solid transparent;border-bottom:8px solid transparent;margin-left:3px}.logo b{font-size:28px}
h1{font-size:22px;margin:0 0 6px}p{color:var(--mute);margin:0 0 18px}input{width:100%;padding:14px 16px;border-radius:12px;border:1px solid var(--line);background:var(--panel);color:var(--text);font:600 18px ui-monospace,Consolas,monospace;letter-spacing:2px;text-transform:uppercase}
input:focus,button:focus-visible{outline:2px solid var(--accent);outline-offset:2px}button{margin-top:12px;width:100%;padding:14px;border:0;border-radius:12px;background:var(--accent);color:#fff;font:600 16px inherit;cursor:pointer}button:disabled{opacity:.6;cursor:default}
button.alt{background:transparent;border:1px solid var(--line);color:var(--text);padding:12px;font-size:15px}
#msg{min-height:1.5em;margin-top:14px;color:var(--err);font-size:14px}small{display:block;margin-top:22px;color:var(--mute)}
#pair{margin-top:16px;border:1px solid var(--line);border-radius:14px;padding:16px;background:var(--panel);text-align:center}#pair p{margin:0;font-size:14px}
#pcode{font:700 42px ui-monospace,Consolas,monospace;letter-spacing:6px;margin:8px 0}#pqr{width:190px;max-width:65%;margin:8px auto 4px}#pqr svg{display:block;width:100%;height:auto;border-radius:8px}</style></head><body><main>
<div class="logo"><i></i><b>MMN</b></div><h1>Enter your access code</h1><p>Access is by invitation. Ask the person who invited you for a code.</p>
<form id="f"><input id="c" autocomplete="off" autocapitalize="characters" spellcheck="false" maxlength="40" placeholder="XXXX-XXXX-XXXX" aria-label="Access code" autofocus><button id="b" type="submit">Continue</button></form>
<button id="pbtn" class="alt" type="button">Use my phone to sign in (for TVs)</button>
<div id="pair" hidden><p>On your phone, scan this code, or open <b id="phost"></b> and type the code:</p><div id="pcode" aria-live="polite">---</div><div id="pqr"></div><p id="pstate" role="status">Getting a code...</p><button id="pagain" class="alt" type="button" hidden>Get a new code</button></div>
<div id="msg" role="alert">__NOTE__</div><small>Your code is private. Do not share it.</small></main>
<script>(function(){var NEXT=__NEXT__;
var f=document.getElementById('f'),c=document.getElementById('c'),b=document.getElementById('b'),m=document.getElementById('msg');
f.onsubmit=function(e){e.preventDefault();if(!c.value.trim())return;b.disabled=true;m.textContent='';
fetch('/gate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code:c.value,next:NEXT})}).then(function(r){return r.json().catch(function(){return{}}).then(function(j){
if(r.ok){location.href=j.next||NEXT||'/app';return}m.textContent=j.error||'Could not check the code. Try again.';b.disabled=false})}).catch(function(){m.textContent='Could not reach the server. Try again.';b.disabled=false})};
var pid=null,timer=null,$=function(i){return document.getElementById(i)};
function stop(){clearInterval(timer);timer=null}
function showQr(url){var q=$('pqr');function put(){try{q.innerHTML=window.qrSvg(url)}catch(e){q.textContent=''}}
if(window.qrSvg)put();else{var s=document.createElement('script');s.src='/qr.js';s.onload=put;document.head.appendChild(s)}}
function poll(){fetch('/pair/poll?id='+encodeURIComponent(pid),{cache:'no-store'}).then(function(r){return r.json()}).then(function(j){
if(j.state==='ok'){stop();$('pstate').textContent='Signed in. Opening...';location.href='/app'}
else if(j.state==='expired'){stop();$('pstate').textContent='This code expired.';$('pagain').hidden=false}
else if(j.state==='devices'){stop();$('pstate').textContent=j.error;$('pagain').hidden=false}}).catch(function(){})}
function start(){stop();$('pagain').hidden=true;$('pstate').textContent='Getting a code...';
fetch('/pair/start',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'}).then(function(r){return r.json().then(function(j){return{ok:r.ok,j:j}})}).then(function(o){
if(!o.ok){$('pstate').textContent=o.j.error||'Could not start.';$('pagain').hidden=false;return}
pid=o.j.id;$('pcode').textContent=o.j.code.slice(0,3)+'-'+o.j.code.slice(3);$('phost').textContent=location.host+'/me';showQr(location.origin+'/me?pair='+o.j.code);
$('pstate').textContent='Waiting for your phone...';timer=setInterval(poll,2000)}).catch(function(){$('pstate').textContent='Could not reach the server.';$('pagain').hidden=false})}
$('pbtn').onclick=function(){$('pair').hidden=false;$('pbtn').hidden=true;start()};$('pagain').onclick=start;
})();</script></body></html>`;
const ME_HTML = String.raw`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex"><title>MMN · My access</title>
<style>:root{--bg:#0d0f1f;--panel:#161938;--raise:#1f2450;--line:#2a2e5c;--text:#eef0ff;--mute:#9aa0d0;--accent:#8b7bff;--ok:#5fd6a0;--warn:#ffb86b;--err:#ff7a8a}*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;padding:20px;padding-top:max(20px,env(safe-area-inset-top))}
main{max-width:720px;margin:0 auto}.top{display:flex;align-items:center;gap:12px;margin-bottom:18px}.logo{display:flex;align-items:center;gap:10px;margin-right:auto}.logo i{width:34px;height:34px;border-radius:10px;background:var(--accent);display:grid;place-items:center}
.logo i:after{content:"";border-left:11px solid #fff;border-top:7px solid transparent;border-bottom:7px solid transparent;margin-left:3px}.logo b{font-size:20px}
a.btn,button{background:var(--raise);color:var(--text);border:1px solid var(--line);border-radius:10px;padding:8px 14px;font:inherit;text-decoration:none;cursor:pointer}a.btn:hover,button:hover{border-color:var(--accent)}button.pri{background:var(--accent);border-color:var(--accent);color:#fff;font-weight:600}button.sm{padding:5px 10px;font-size:14px}button.danger{color:var(--err)}
h1{font-size:24px;margin:0 0 14px}h2{font-size:16px;margin:0 0 6px}.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:16px;margin-bottom:12px}.small{color:var(--mute);font-size:14px;margin:0 0 10px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-bottom:12px}.tile{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:12px 14px}.tile b{display:block;font-size:22px;line-height:1.25}.tile span{color:var(--mute);font-size:13px}
.row{display:flex;align-items:center;gap:10px;padding:10px 0;border-bottom:1px solid var(--line)}.row:last-child{border-bottom:0}.row .t{flex:1;min-width:0}.row .t div:last-child{color:var(--mute);font-size:13px}
.tag{font-size:12px;border:1px solid #235c3b;color:var(--ok);border-radius:99px;padding:1px 8px;margin-left:6px}input{width:100%;max-width:220px;padding:11px 12px;border-radius:10px;border:1px solid var(--line);background:#0d1328;color:var(--text);font:600 18px ui-monospace,Consolas,monospace;letter-spacing:3px;text-transform:uppercase}
input:focus,button:focus-visible,a:focus-visible{outline:2px solid var(--accent);outline-offset:2px}#perr,#pok{min-height:1.4em;font-size:14px;margin-top:8px}#perr{color:var(--err)}#pok{color:var(--ok)}
#toast{position:fixed;left:50%;bottom:20px;transform:translateX(-50%);background:var(--raise);border:1px solid var(--accent);border-radius:10px;padding:10px 16px;max-width:90vw}[hidden]{display:none!important}</style></head><body><main>
<div class="top"><div class="logo"><i></i><b>MMN</b></div><a class="btn" href="/app">Back to player</a></div>
<h1 id="hello">My access</h1>
<div class="tiles"><div class="tile"><b id="t1">-</b><span>Access</span></div><div class="tile"><b id="t2">-</b><span>Data used today</span></div><div class="tile"><b id="t3">-</b><span>Data used this month</span></div></div>
<div class="card"><h2>My devices <span id="dcount" class="small"></span></h2><p class="small">Remove a device you no longer use to free its place. It is signed out straight away.</p><div id="devs"></div></div>
<div class="card"><h2>Sign in a TV</h2><p class="small">On the TV, open this site and choose "Use my phone to sign in". Then type the code shown on the TV here, or scan the TV's QR code.</p>
<input id="pc" maxlength="8" autocomplete="off" autocapitalize="characters" spellcheck="false" placeholder="ABC-123" aria-label="Code shown on the TV"> <button id="pcheck" class="pri">Check</button>
<div id="pconf" hidden class="card" style="margin:12px 0 0;background:#10143a"><div id="pwho"></div><p class="small" style="margin:8px 0">Only approve if you are looking at this code on your own TV right now.</p><button id="pyes" class="pri">Approve</button> <button id="pno">Cancel</button></div>
<div id="perr" role="alert"></div><div id="pok" role="status"></div></div>
<div id="toast" role="status" hidden></div></main>
<script>(function(){var $=function(i){return document.getElementById(i)},cur=null;
function api(m,p,b){return fetch(p,{method:m,headers:{'Content-Type':'application/json','X-Me':'1'},body:b?JSON.stringify(b):undefined,cache:'no-store'}).then(function(r){return r.json().catch(function(){return{}}).then(function(j){
if(r.status===401){location.href='/gate?next=/me';throw new Error('login')}if(!r.ok)throw new Error(j.error||('Error '+r.status));return j})})}
function toast(t){var e=$('toast');e.textContent=t;e.hidden=false;clearTimeout(toast.t);toast.t=setTimeout(function(){e.hidden=true},2800)}
function mb(n){return n>=1000?(n/1000).toFixed(1)+' GB':Math.round(n)+' MB'}
function ago(t,now){var s=Math.max(0,Math.round((now-t)/1000));if(s<90)return'just now';if(s<5400)return Math.round(s/60)+' min ago';if(s<172800)return Math.round(s/3600)+' h ago';return Math.round(s/86400)+' days ago'}
function load(){api('GET','/me/api').then(function(d){
$('hello').textContent='Hi '+d.name;
var left=d.expires==null?null:Math.ceil((d.expires-d.now)/86400000);
$('t1').textContent=d.expires==null?'No end date':(left>90?'Until '+new Date(d.expires).toLocaleDateString(undefined,{day:'numeric',month:'short',year:'numeric'}):left>1?left+' days left':left===1?'1 day left':'Ends today');
$('t2').textContent=mb(d.usage.today);$('t3').textContent=mb(d.usage.month);
$('dcount').textContent=d.devices.length+' of '+d.limit+' used';
var h=$('devs');h.textContent='';
if(!d.devices.length){var e=document.createElement('p');e.className='small';e.textContent='No devices yet.';h.appendChild(e)}
d.devices.forEach(function(x){var row=document.createElement('div'),t=document.createElement('div'),a=document.createElement('div'),b=document.createElement('div'),bt=document.createElement('button');
row.className='row';t.className='t';a.textContent=x.label;if(x.current){var g=document.createElement('span');g.className='tag';g.textContent='This device';a.appendChild(g)}
b.textContent='Last used '+ago(x.last,d.now);t.append(a,b);bt.className='sm danger';bt.textContent=x.current?'Sign out':'Remove';
bt.onclick=function(){if(!confirm(x.current?'Sign out of this device?':'Remove '+x.label+'? It is signed out straight away.'))return;
api('POST','/me/api/device/remove',{id:x.id}).then(function(r){if(r.self){location.href='/gate';return}toast('Device removed');load()}).catch(function(er){if(er.message!=='login')toast(er.message)})};
row.append(t,bt);h.appendChild(row)})}).catch(function(e){if(e.message!=='login')toast(e.message)})}
function check(){$('perr').textContent='';$('pok').textContent='';$('pconf').hidden=true;var c=$('pc').value.trim();if(!c)return;
api('POST','/me/api/pair/lookup',{code:c}).then(function(r){cur=c;$('pwho').textContent=r.label+' is asking to sign in to your access.';$('pconf').hidden=false}).catch(function(e){if(e.message!=='login')$('perr').textContent=e.message})}
$('pcheck').onclick=check;$('pc').onkeydown=function(e){if(e.key==='Enter')check()};
$('pno').onclick=function(){$('pconf').hidden=true;cur=null};
$('pyes').onclick=function(){api('POST','/me/api/pair/approve',{code:cur}).then(function(){$('pconf').hidden=true;$('pc').value='';$('pok').textContent='Approved. Your TV will sign in in a few seconds.';load()}).catch(function(e){if(e.message!=='login'){$('perr').textContent=e.message;$('pconf').hidden=true}})};
var q=new URLSearchParams(location.search).get('pair');if(q){$('pc').value=q;history.replaceState(null,'','/me');check()}
load();})();</script></body></html>`;
const QR_JS = "/* Tiny QR code generator (byte mode, error correction M, versions 1-10). window.qrSvg(text) returns an SVG string. */\n(function (root) {\n  'use strict';\n  var EXP = new Uint8Array(512), LOG = new Uint8Array(256);\n  for (var i = 0, x = 1; i < 255; i++) { EXP[i] = x; LOG[x] = i; x <<= 1; if (x & 256) x ^= 0x11d; }\n  for (i = 255; i < 512; i++) EXP[i] = EXP[i - 255];\n  function mul(a, b) { return a && b ? EXP[LOG[a] + LOG[b]] : 0; }\n  function rsGen(n) { var g = [1]; for (var i = 0; i < n; i++) { var ng = new Array(g.length + 1).fill(0); for (var j = 0; j < g.length; j++) { ng[j] ^= g[j]; ng[j + 1] ^= mul(g[j], EXP[i]); } g = ng; } return g; }\n  function rsEnc(data, n) { var g = rsGen(n), res = new Array(n).fill(0); for (var k = 0; k < data.length; k++) { var f = data[k] ^ res.shift(); res.push(0); if (f) for (var i = 0; i < n; i++) res[i] ^= mul(g[i + 1], f); } return res; }\n  var VER = { 1: [10, [[1, 16]]], 2: [16, [[1, 28]]], 3: [26, [[1, 44]]], 4: [18, [[2, 32]]], 5: [24, [[2, 43]]], 6: [16, [[4, 27]]], 7: [18, [[4, 31]]], 8: [22, [[2, 38], [2, 39]]], 9: [22, [[3, 36], [2, 37]]], 10: [26, [[4, 43], [1, 44]]] };\n  var ALIGN = { 1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30], 6: [6, 34], 7: [6, 22, 38], 8: [6, 24, 42], 9: [6, 26, 46], 10: [6, 28, 50] };\n  function dataCw(v) { return VER[v][1].reduce(function (a, b) { return a + b[0] * b[1]; }, 0); }\n  function utf8(s) { if (typeof TextEncoder !== 'undefined') return Array.prototype.slice.call(new TextEncoder().encode(s)); var e = unescape(encodeURIComponent(s)), o = []; for (var i = 0; i < e.length; i++) o.push(e.charCodeAt(i)); return o; }\n  function bit(n, i) { return ((n >>> i) & 1) !== 0; }\n  function matrix(text, forceMask) {\n    var bytes = utf8(String(text)), v = 0;\n    for (var t = 1; t <= 10; t++) { if (4 + (t < 10 ? 8 : 16) + 8 * bytes.length <= dataCw(t) * 8) { v = t; break; } }\n    if (!v) throw new Error('Text is too long for the QR code');\n    var bits = [];\n    function put(val, len) { for (var i = len - 1; i >= 0; i--) bits.push((val >>> i) & 1); }\n    put(4, 4); put(bytes.length, v < 10 ? 8 : 16); bytes.forEach(function (b) { put(b, 8); });\n    var cap = dataCw(v) * 8; put(0, Math.min(4, cap - bits.length)); while (bits.length % 8) bits.push(0);\n    var cw = []; for (var i = 0; i < bits.length; i += 8) { var b = 0; for (var j = 0; j < 8; j++) b = (b << 1) | bits[i + j]; cw.push(b); }\n    for (var pad = 0xec; cw.length < dataCw(v); pad ^= 0xec ^ 0x11) cw.push(pad);\n    var ecLen = VER[v][0], blocks = [], pos = 0;\n    VER[v][1].forEach(function (g) { for (var c = 0; c < g[0]; c++) { var d = cw.slice(pos, pos + g[1]); pos += g[1]; blocks.push({ d: d, e: rsEnc(d, ecLen) }); } });\n    var all = [], maxD = Math.max.apply(null, blocks.map(function (b) { return b.d.length; }));\n    for (i = 0; i < maxD; i++) blocks.forEach(function (b) { if (i < b.d.length) all.push(b.d[i]); });\n    for (i = 0; i < ecLen; i++) blocks.forEach(function (b) { all.push(b.e[i]); });\n    var size = 17 + 4 * v, M = [], F = [];\n    for (i = 0; i < size; i++) { M.push(new Array(size).fill(false)); F.push(new Array(size).fill(false)); }\n    function setF(x, y, dark) { M[y][x] = dark; F[y][x] = true; }\n    for (i = 0; i < size; i++) { setF(6, i, i % 2 === 0); setF(i, 6, i % 2 === 0); }\n    function finder(cx, cy) { for (var dy = -4; dy <= 4; dy++) for (var dx = -4; dx <= 4; dx++) { var d = Math.max(Math.abs(dx), Math.abs(dy)), xx = cx + dx, yy = cy + dy; if (xx >= 0 && xx < size && yy >= 0 && yy < size) setF(xx, yy, d !== 2 && d !== 4); } }\n    finder(3, 3); finder(size - 4, 3); finder(3, size - 4);\n    var al = ALIGN[v], last = al.length - 1;\n    al.forEach(function (ax, ai) { al.forEach(function (ay, aj) { if ((ai === 0 && aj === 0) || (ai === 0 && aj === last) || (ai === last && aj === 0)) return; for (var dy = -2; dy <= 2; dy++) for (var dx = -2; dx <= 2; dx++) setF(ax + dx, ay + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1); }); });\n    function formatBits(mask) { var data = (0 << 3) | mask, rem = data; for (var i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537); return ((data << 10) | rem) ^ 0x5412; }\n    function drawFormat(mask) {\n      var b = formatBits(mask), i;\n      for (i = 0; i <= 5; i++) setF(8, i, bit(b, i)); setF(8, 7, bit(b, 6)); setF(8, 8, bit(b, 7)); setF(7, 8, bit(b, 8));\n      for (i = 9; i < 15; i++) setF(14 - i, 8, bit(b, i));\n      for (i = 0; i < 8; i++) setF(size - 1 - i, 8, bit(b, i));\n      for (i = 8; i < 15; i++) setF(8, size - 15 + i, bit(b, i));\n      setF(8, size - 8, true);\n    }\n    drawFormat(0);\n    if (v >= 7) { var rem = v; for (i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25); var vb = (v << 12) | rem; for (i = 0; i < 18; i++) { var a = size - 11 + (i % 3), bb = Math.floor(i / 3), db = bit(vb, i); setF(a, bb, db); setF(bb, a, db); } }\n    var k = 0;\n    for (var right = size - 1; right >= 1; right -= 2) {\n      if (right === 6) right = 5;\n      for (var vert = 0; vert < size; vert++) for (var jj = 0; jj < 2; jj++) {\n        var xx = right - jj, up = ((right + 1) & 2) === 0, yy = up ? size - 1 - vert : vert;\n        if (!F[yy][xx] && k < all.length * 8) { M[yy][xx] = bit(all[k >>> 3], 7 - (k & 7)); k++; }\n      }\n    }\n    function applyMask(mask) {\n      for (var y = 0; y < size; y++) for (var x = 0; x < size; x++) {\n        var inv; switch (mask) { case 0: inv = (x + y) % 2 === 0; break; case 1: inv = y % 2 === 0; break; case 2: inv = x % 3 === 0; break; case 3: inv = (x + y) % 3 === 0; break;\n          case 4: inv = (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0; break; case 5: inv = x * y % 2 + x * y % 3 === 0; break; case 6: inv = (x * y % 2 + x * y % 3) % 2 === 0; break; default: inv = ((x + y) % 2 + x * y % 3) % 2 === 0; }\n        if (!F[y][x] && inv) M[y][x] = !M[y][x];\n      }\n    }\n    function penalty() {\n      var p = 0, y, x, run, i;\n      function lines(get) { for (var a = 0; a < size; a++) { run = 1; for (var b = 1; b < size; b++) { if (get(a, b) === get(a, b - 1)) { run++; if (run === 5) p += 3; else if (run > 5) p++; } else run = 1; } } }\n      lines(function (a, b) { return M[a][b]; }); lines(function (a, b) { return M[b][a]; });\n      for (y = 0; y < size - 1; y++) for (x = 0; x < size - 1; x++) { var c = M[y][x]; if (c === M[y][x + 1] && c === M[y + 1][x] && c === M[y + 1][x + 1]) p += 3; }\n      var pat1 = '10111010000', pat2 = '00001011101';\n      for (var a = 0; a < size; a++) { var r = '', cc = ''; for (var b = 0; b < size; b++) { r += M[a][b] ? '1' : '0'; cc += M[b][a] ? '1' : '0'; }\n        [r, cc].forEach(function (s) { for (i = 0; i + 11 <= s.length; i++) { var sub = s.substr(i, 11); if (sub === pat1 || sub === pat2) p += 40; } }); }\n      var dark = 0; for (y = 0; y < size; y++) for (x = 0; x < size; x++) if (M[y][x]) dark++;\n      var tot = size * size, kk = Math.ceil(Math.abs(dark * 20 - tot * 10) / tot) - 1; if (kk > 0) p += kk * 10;\n      return p;\n    }\n    var best = forceMask, bestP = Infinity;\n    if (best === undefined) { for (var m = 0; m < 8; m++) { applyMask(m); drawFormat(m); var pp = penalty(); if (pp < bestP) { bestP = pp; best = m; } applyMask(m); } }\n    applyMask(best); drawFormat(best);\n    return { size: size, version: v, mask: best, get: function (x, y) { return M[y][x]; } };\n  }\n  function svg(text, opt) {\n    opt = opt || {}; var q = matrix(text), m = opt.margin == null ? 4 : opt.margin, n = q.size + 2 * m, d = '';\n    for (var y = 0; y < q.size; y++) { var x = 0; while (x < q.size) { if (q.get(x, y)) { var s = x; while (x < q.size && q.get(x, y)) x++; d += 'M' + (s + m) + ' ' + (y + m) + 'h' + (x - s) + 'v1h-' + (x - s) + 'z'; } else x++; } }\n    return '<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 ' + n + ' ' + n + '\" shape-rendering=\"crispEdges\" role=\"img\" aria-label=\"' + (opt.label || 'QR code') + '\"><rect width=\"' + n + '\" height=\"' + n + '\" fill=\"#fff\"/><path d=\"' + d + '\" fill=\"#000\"/></svg>';\n  }\n  root.qrSvg = svg; root.qrMatrix = matrix;\n})(typeof window !== 'undefined' ? window : globalThis);\n";
function gatePage(why, next) { return GATE_HTML.replace('__NOTE__', WHY[why] || '').replace('__NEXT__', JSON.stringify(safeNext(next))); }
function readBody(req, max = 8192) {
  return new Promise((resolve, reject) => {
    let n = 0; const ch = [];
    req.on('data', c => { n += c.length; if (n > max) { reject(new Error('too big')); req.destroy(); return; } ch.push(c); });
    req.on('end', () => resolve(Buffer.concat(ch).toString())); req.on('error', reject);
  });
}
function acceptsEnc(req, enc) { return new RegExp('\\b' + enc + '\\b').test(String((req && req.headers['accept-encoding']) || '')); }
function sendJson(res, code, o, extra) {
  const h = { ...SEC, 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...(extra || {}) };
  let body = Buffer.from(JSON.stringify(o));
  if (body.length > 1024 && acceptsEnc(res.req, 'gzip')) { body = zlib.gzipSync(body, { level: 5 }); h['Content-Encoding'] = 'gzip'; h.Vary = 'Accept-Encoding'; }
  h['Content-Length'] = body.length; res.writeHead(code, h); res.end(body);
}
const STATIC = new Map();   // file -> prepared copy (raw, gzip, brotli, etag); rebuilt only when the file changes
function staticPage(file, transform) {
  const fp = path.join(__dirname, file), st = fs.statSync(fp); let c = STATIC.get(file);
  if (!c || c.mtime !== st.mtimeMs) {
    let raw = fs.readFileSync(fp, 'utf8'); if (transform) raw = transform(raw);
    const buf = Buffer.from(raw);
    c = { mtime: st.mtimeMs, raw: buf, gz: zlib.gzipSync(buf, { level: 9 }), br: zlib.brotliCompressSync(buf, { params: { [zlib.constants.BROTLI_PARAM_QUALITY]: 9 } }), etag: 'W/"' + crypto.createHash('sha1').update(buf).digest('hex').slice(0, 16) + '"' };
    STATIC.set(file, c);
  }
  return c;
}
function sendStatic(req, res, c, type) {
  const h = { ...SEC, 'Content-Type': type, 'Cache-Control': 'no-cache', ETag: c.etag, Vary: 'Accept-Encoding' };
  const inm = String(req.headers['if-none-match'] || '');
  if (inm && inm.split(',').some(x => x.trim() === c.etag)) { res.writeHead(304, h); return res.end(); }
  let body = c.raw;
  if (acceptsEnc(req, 'br')) { body = c.br; h['Content-Encoding'] = 'br'; } else if (acceptsEnc(req, 'gzip')) { body = c.gz; h['Content-Encoding'] = 'gzip'; }
  h['Content-Length'] = body.length; res.writeHead(200, h); res.end(req.method === 'HEAD' ? undefined : body);
}
/* channel lists (get_live_streams ...) are big, rarely change and are asked for again at every visit: keep a compressed copy for a few minutes */
const LIST_TTL = (+process.env.LIST_CACHE_SECONDS || 300) * 1000, LIST_MAX = (+process.env.LIST_CACHE_MB || 80) * 1048576, LIST_RAW_MAX = 64 * 1048576;
const LIST_ACTIONS = new Set(['get_live_categories', 'get_live_streams', 'get_vod_categories', 'get_vod_streams', 'get_series_categories', 'get_series']);
const LISTC = new Map(); let listBytes = 0;
const LIST_HDR = 'private, max-age=' + Math.round(LIST_TTL / 1000) + ', stale-while-revalidate=86400';
function listActionOf(t) { try { const x = new URL(t); return /\/player_api\.php$/i.test(x.pathname) && LIST_ACTIONS.has(x.searchParams.get('action')) ? x.searchParams.get('action') : ''; } catch { return ''; } }
function listGet(key) { const e = LISTC.get(key); if (!e) return null; if (Date.now() - e.t > LIST_TTL) { listBytes -= e.gz.length; LISTC.delete(key); return null; } return e; }
function listSet(key, e) {
  if (e.gz.length > LIST_MAX / 3) return;
  const old = LISTC.get(key); if (old) { listBytes -= old.gz.length; LISTC.delete(key); }
  LISTC.set(key, e); listBytes += e.gz.length;
  for (const [k, v] of LISTC) { if (listBytes <= LIST_MAX) break; listBytes -= v.gz.length; LISTC.delete(k); }
}
setInterval(() => { for (const k of [...LISTC.keys()]) listGet(k); }, 60000).unref();
function sendList(req, res, e) {
  const h = { ...SEC, 'Content-Type': e.ct, 'Cache-Control': LIST_HDR, Vary: 'Accept-Encoding' };
  if (acceptsEnc(req, 'gzip')) { h['Content-Encoding'] = 'gzip'; h['Content-Length'] = e.gz.length; res.writeHead(200, h); return res.end(e.gz); }
  const raw = zlib.gunzipSync(e.gz); h['Content-Length'] = raw.length; res.writeHead(200, h); res.end(raw);
}

async function handleGate(req, res, u) {
  if (!gateOn()) { res.writeHead(302, { Location: '/app' }); return res.end(); }
  if (req.method === 'GET') {
    if (!memberOf(req).error && !u.searchParams.get('why')) { res.writeHead(302, { Location: safeNext(u.searchParams.get('next')) || '/app' }); return res.end(); }
    res.writeHead(200, { ...SEC, 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    return res.end(gatePage(u.searchParams.get('why') || '', u.searchParams.get('next') || ''));
  }
  if (req.method !== 'POST') return fail(res, 405, 'GET or POST only');
  const site = req.headers['sec-fetch-site']; if (site && site !== 'same-origin') return fail(res, 403, 'Same-origin requests only');
  const ip = clientIp(req), now = Date.now();
  let t = tries.get(ip); if (!t || t.reset < now) { t = { n: 0, reset: now + 15 * 60000 }; tries.set(ip, t); }
  if (t.n >= 10) return sendJson(res, 429, { error: 'Too many wrong attempts. Please try again in a few minutes.' });
  let code = '', nextP = '';
  try { const raw = await readBody(req); try { const j = JSON.parse(raw); code = j.code; nextP = j.next; } catch { const q = new URLSearchParams(raw); code = q.get('code'); nextP = q.get('next'); } } catch { return sendJson(res, 400, { error: 'Bad request' }); }
  const h = hashCode(code);
  let found = null; for (const x of HASHES) if (crypto.timingSafeEqual(h, x.hash)) found = x.m;   // checks every code, so timing reveals nothing
  if (!found || !normCode(code)) { t.n++; console.log('[access] wrong code from ' + ip); return sendJson(res, 401, { error: 'That code is not valid.' }); }
  if (found.paused) return sendJson(res, 401, { error: WHY.paused });
  if (Date.now() > expOf(found)) return sendJson(res, 401, { error: 'This code expired on ' + dateStr(found.expires) + '.' });
  const ss = startSession(req, found);
  if (ss.error) { console.log('[access] ' + found.name + ' refused: device limit (' + found.devices + ')'); return sendJson(res, 401, { error: ss.error }); }
  console.log('[access] sign-in ok member=' + found.name + ' device=' + ss.device.slice(0, 4) + ' (' + ss.count + '/' + found.devices + ' devices)');
  return sendJson(res, 200, { ok: true, next: safeNext(nextP) || '' }, { 'Set-Cookie': ss.cookie });
}

/* ---------- pair a TV with a phone ---------- */
const PAIRS = new Map(), PAIRCODES = new Map(), pairStarts = new Map(), pairTries = new Map();
setInterval(() => { const now = Date.now(); for (const [id, p] of PAIRS) if (p.exp < now) { PAIRS.delete(id); PAIRCODES.delete(p.code); } }, 30000).unref();
function newPairCode() { for (;;) { const b = crypto.randomBytes(6); let c = ''; for (const x of b) c += ALPHA[x % ALPHA.length]; if (!PAIRCODES.has(c)) return c; } }
function pairFromCode(raw) { const code = String(raw || '').toUpperCase().replace(/[^A-Z0-9]/g, ''), id = PAIRCODES.get(code), p = id && PAIRS.get(id); return p && p.exp > Date.now() ? p : null; }
async function handlePair(req, res, u) {
  if (!gateOn()) return fail(res, 404, 'Not found');
  if (u.pathname === '/pair/start' && req.method === 'POST') {
    const site = req.headers['sec-fetch-site']; if (site && site !== 'same-origin') return fail(res, 403, 'Same-origin requests only');
    const ip = clientIp(req), now = Date.now(); let t = pairStarts.get(ip); if (!t || t.reset < now) { t = { n: 0, reset: now + 60000 }; pairStarts.set(ip, t); }
    if (++t.n > 8) return sendJson(res, 429, { error: 'Too many tries. Please wait a minute.' });
    if (PAIRS.size > 2000) return sendJson(res, 503, { error: 'Busy. Try again in a moment.' });
    const id = crypto.randomBytes(18).toString('base64url'), code = newPairCode();
    PAIRS.set(id, { id, code, label: deviceLabel(req.headers['user-agent']), created: now, exp: now + 600000, state: 'waiting', fp: null, epoch: 0 }); PAIRCODES.set(code, id);
    return sendJson(res, 200, { id, code, ttl: 600 });
  }
  if (u.pathname === '/pair/poll' && req.method === 'GET') {
    const p = PAIRS.get(u.searchParams.get('id') || '');
    if (!p || p.exp < Date.now()) return sendJson(res, 200, { state: 'expired' });
    if (p.state !== 'approved') return sendJson(res, 200, { state: 'waiting' });
    PAIRS.delete(p.id); PAIRCODES.delete(p.code);                       // a code works once
    const m = BYFP.get(p.fp);
    if (!m || m.paused || Date.now() > expOf(m) || (m.epoch | 0) !== (p.epoch | 0)) return sendJson(res, 200, { state: 'expired' });
    const ss = startSession(req, m);
    if (ss.error) return sendJson(res, 200, { state: 'devices', error: ss.error });
    console.log('[access] TV paired member=' + m.name + ' device=' + ss.device.slice(0, 4));
    return sendJson(res, 200, { state: 'ok' }, { 'Set-Cookie': ss.cookie });
  }
  return fail(res, 404, 'Not found');
}

/* ---------- My access page + continue on another device ---------- */
const HAND = new Map();   // token -> { fp, data, exp }
setInterval(() => { const now = Date.now(); for (const [k, v] of HAND) if (v.exp < now) HAND.delete(k); }, 60000).unref();
function meInfo(w) {
  const e = w.entry, devs = DEVICES.get(e.fp) || new Map(); pruneDevices(devs);
  const list = [...devs.entries()].map(([id, t]) => { const mt = DEVMETA.get(id) || {}; return { id, label: mt.label || 'Device', last: t, first: mt.first || null, current: id === w.device }; }).sort((a, b) => (b.current - a.current) || (b.last - a.last));
  return { name: e.name, expires: e.expires, limit: e.devices, screens: e.screens, usage: usageOf(e), devices: list, now: Date.now() };
}
async function handleMe(req, res, u, w) {
  const p = u.pathname;
  if (req.method !== 'GET') { const site = req.headers['sec-fetch-site']; if ((site && site !== 'same-origin') || req.headers['x-me'] !== '1') return fail(res, 403, 'Not allowed'); }
  const ip = clientIp(req), now = Date.now();
  const bad = () => { let t = pairTries.get(ip); if (!t || t.reset < now) { t = { n: 0, reset: now + 15 * 60000 }; pairTries.set(ip, t); } t.n++; };
  const blocked = () => { const t = pairTries.get(ip); return t && t.reset >= now && t.n >= 12; };
  try {
    if (p === '/me/api' && req.method === 'GET') return sendJson(res, 200, meInfo(w));
    if (p === '/me/api/device/remove' && req.method === 'POST') {
      const id = String(JSON.parse(await readBody(req) || '{}').id || '');
      if (!/^[a-f0-9]{16}$/.test(id)) throw new Error('Bad device');
      const devs = DEVICES.get(w.entry.fp); if (!devs || !devs.has(id)) throw new Error('That device is not on the list any more');
      devs.delete(id); DEVMETA.delete(id); const rv = w.entry.revoked || (w.entry.revoked = []); rv.push(id); if (rv.length > 100) rv.shift();
      killDevice(w.entry.fp, id); saveStore(); console.log('[access] ' + w.entry.name + ' removed a device');
      return sendJson(res, 200, { ok: true, self: id === w.device });
    }
    if ((p === '/me/api/pair/lookup' || p === '/me/api/pair/approve') && req.method === 'POST') {
      if (blocked()) return sendJson(res, 429, { error: 'Too many wrong codes. Try again in a few minutes.' });
      const pr = pairFromCode(JSON.parse(await readBody(req) || '{}').code);
      if (!pr || pr.state === 'approved') { bad(); throw new Error('That code was not found. It may have expired. Ask the TV for a new one.'); }
      if (p.endsWith('lookup')) return sendJson(res, 200, { ok: true, label: pr.label, age: Math.round((now - pr.created) / 1000) });
      const devs = DEVICES.get(w.entry.fp) || new Map(); pruneDevices(devs);
      if (devs.size >= w.entry.devices) throw new Error('Your code is already on its limit of ' + w.entry.devices + ' device' + (w.entry.devices > 1 ? 's' : '') + '. Remove one above first.');
      pr.state = 'approved'; pr.fp = w.entry.fp; pr.epoch = w.entry.epoch | 0;
      console.log('[access] ' + w.entry.name + ' approved a TV'); return sendJson(res, 200, { ok: true });
    }
    if (p === '/me/api/handoff' && req.method === 'POST') {
      const b = JSON.parse(await readBody(req) || '{}');
      if (!['live', 'movie', 'episode'].includes(b.kind)) throw new Error('Bad request');
      if (!/^[A-Za-z0-9_-]{1,40}$/.test(String(b.id || '')) || !/^[a-z0-9]{2,5}$/.test(String(b.ext || ''))) throw new Error('This title cannot be sent. Handoff works with Xtream logins.');
      const data = { kind: b.kind, id: String(b.id), ext: String(b.ext), name: String(b.name || '').slice(0, 120), series: String(b.series || '').slice(0, 120), pos: Math.max(0, Math.min(864000, Math.floor(+b.pos || 0))) };
      const mine = [...HAND.entries()].filter(([, v]) => v.fp === w.entry.fp); if (mine.length >= 20) HAND.delete(mine[0][0]);
      const token = crypto.randomBytes(12).toString('base64url'); HAND.set(token, { fp: w.entry.fp, data, exp: now + 15 * 60000 });
      return sendJson(res, 200, { ok: true, token, path: '/h/' + token, ttl: 900 });
    }
    const hm = /^\/me\/api\/handoff\/([A-Za-z0-9_-]{6,40})$/.exec(p);
    if (hm && req.method === 'GET') {
      const v = HAND.get(hm[1]); if (!v || v.exp < now || v.fp !== w.entry.fp) return sendJson(res, 404, { error: 'This link has expired, or it belongs to another member.' });
      return sendJson(res, 200, { ok: true, ...v.data });
    }
    return sendJson(res, 404, { error: 'Not found' });
  } catch (e) { return sendJson(res, 400, { error: e.message || 'Bad request' }); }
}
function staticText(key, text) {           // like staticPage, for pages kept inside this file
  let c = STATIC.get(key);
  if (!c) { const buf = Buffer.from(text); c = { mtime: 0, raw: buf, gz: zlib.gzipSync(buf, { level: 9 }), br: zlib.brotliCompressSync(buf, { params: { [zlib.constants.BROTLI_PARAM_QUALITY]: 9 } }), etag: 'W/"' + crypto.createHash('sha1').update(buf).digest('hex').slice(0, 16) + '"' }; STATIC.set(key, c); }
  return c;
}

/* ---------- admin ---------- */
const adminHash = ADMIN_PASSWORD ? crypto.createHash('sha256').update(ADMIN_PASSWORD).digest() : null;
const adminOk = req => { const p = verify(cookieOf(req, 'mmn_admin')); return !!(p && p.a === 1 && p.x > Date.now()); };
function insights(days) {
  days = [7, 30, 60].includes(days) ? days : 30;
  const now = Date.now(), keys = []; for (let i = days - 1; i >= 0; i--) keys.push(istDay(now - i * 86400000));
  const today = istDay(now), mon = today.slice(0, 7);
  const daily = keys.map(d => ({ d, mb: Math.round(STORE.daily[d] || 0), peak: STORE.peak[d] || 0 }));
  const hourly = new Array(24).fill(0); let hourDays = 0;
  for (const d of keys) { const H = STORE.hourly[d]; if (H) { hourDays++; for (let h = 0; h < 24; h++) hourly[h] += H[h] || 0; } }
  const T = new Map();
  for (const d of keys) { const D = STORE.titles[d]; if (!D) continue; for (const [key, v] of Object.entries(D)) { const i = key.indexOf('|'), e = T.get(key) || { k: key.slice(0, i), name: key.slice(i + 1), views: 0, mb: 0 }; e.views += v[0] || 0; e.mb += v[1] || 0; T.set(key, e); } }
  const titles = [...T.values()].map(e => ({ ...e, mb: Math.round(e.mb) }));
  const topMb = titles.slice().sort((a, b) => b.mb - a.mb).slice(0, 15), topViews = titles.slice().sort((a, b) => b.views - a.views || b.mb - a.mb).slice(0, 15);
  const members = STORE.members.map(m => { const u = STORE.usage[m.id] || {}; let mb = 0; for (const d of keys) mb += u[d] || 0; return { name: m.name, mb: Math.round(mb) }; }).filter(x => x.mb > 0).sort((a, b) => b.mb - a.mb).slice(0, 8);
  const cut = now - 14 * 86400000;
  const inactive = STORE.members.filter(m => !m.paused && expOf(m) > now && (!m.lastSeenAt || m.lastSeenAt < cut))
    .map(m => ({ name: m.name, days: m.lastSeenAt ? Math.floor((now - m.lastSeenAt) / 86400000) : null, expires: m.expires }))
    .sort((a, b) => (b.days == null ? 9999 : b.days) - (a.days == null ? 9999 : a.days)).slice(0, 20);
  let month = 0; for (const [d, v] of Object.entries(STORE.daily)) if (d.startsWith(mon)) month += v;
  const ist = new Date(now + 19800000), elapsed = (+today.slice(8) - 1) + (ist.getUTCHours() * 60 + ist.getUTCMinutes()) / 1440, dim = new Date(+today.slice(0, 4), +today.slice(5, 7), 0).getDate();
  return { days, now, daily, hourly: hourly.map(Math.round), hourDays, topMb, topViews, members, inactive, titlesTracked: titles.length,
    totals: { today: Math.round(STORE.daily[today] || 0), month: Math.round(month), projected: elapsed >= 0.5 ? Math.round(month / elapsed * dim) : null, daysInMonth: dim } };
}
function memberView(m) {
  const devs = DEVICES.get(m.fp); if (devs) pruneDevices(devs);
  const st = STREAMS.get(m.fp); let watching = 0; if (st) for (const c of st.values()) if (c > 0) watching++;
  let last = m.lastSeenAt || 0; if (devs) for (const t of devs.values()) last = Math.max(last, t);
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
    try { return sendStatic(req, res, staticPage('admin.html'), 'text/html; charset=utf-8'); } catch { return fail(res, 500, 'admin.html is missing from the server files'); }
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
    if (p === '/admin/api/insights' && req.method === 'GET') return sendJson(res, 200, insights(+u.searchParams.get('days') || 30));
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

/* Any unexpected error is logged and answered with a 500 instead of crashing the whole server (a crash shows up as 502 for everyone). */
process.on('unhandledRejection', e => console.log('[error] unhandled: ' + (e && e.stack || e)));
process.on('uncaughtException', e => console.log('[error] uncaught: ' + (e && e.stack || e)));
const server = http.createServer((req, res) => {
  handle(req, res).catch(e => {
    console.log('[error] ' + req.method + ' ' + String(req.url).split('?')[0] + ': ' + (e && e.stack || e));
    try { if (!res.headersSent) res.writeHead(500, { 'Content-Type': 'text/plain' }); res.end('Server error'); } catch {}
  });
});
async function handle(req, res) {
  const u = new URL(req.url, 'http://localhost');
  if (u.pathname === '/healthz') return fail(res, 200, 'ok');
  if (u.pathname === '/' || u.pathname === '/index.html') {
    try { return sendStatic(req, res, staticPage('landing.html'), 'text/html; charset=utf-8'); } catch { return fail(res, 500, 'landing.html not found'); }
  }
  if (u.pathname === '/qr.js') { res.writeHead(200, { 'Content-Type': 'application/javascript; charset=utf-8', 'Cache-Control': 'public, max-age=86400', 'X-Content-Type-Options': 'nosniff' }); return res.end(QR_JS); }
  if (u.pathname.startsWith('/pair/')) return handlePair(req, res, u);
  if (!gateOn() && (u.pathname === '/me' || u.pathname.startsWith('/me/'))) { res.writeHead(302, { Location: '/app' }); return res.end(); }
  if (u.pathname === '/admin' || u.pathname.startsWith('/admin/')) return handleAdmin(req, res, u);
  if (u.pathname === '/gate') return handleGate(req, res, u);
  if (u.pathname === '/logout') { res.writeHead(302, { Location: '/gate', 'Set-Cookie': setCookie(req, 'mmn_session', '', 0), 'Cache-Control': 'no-store' }); return res.end(); }
  let who = null;
  if (gateOn()) {
    const isHand = /^\/h\/[A-Za-z0-9_-]{6,40}$/.test(u.pathname), isPage = u.pathname === '/app' || u.pathname === '/me' || isHand, isMeApi = u.pathname.startsWith('/me/api');
    if (isPage || isMeApi || u.pathname === '/proxy' || u.pathname === '/diag' || u.pathname === '/session') {
      const m = memberOf(req);
      if (m.error) {
        if (isPage) { res.writeHead(302, { Location: gateUrl(u.pathname === '/me' ? '/me' + u.search : u.pathname, m.error), 'Cache-Control': 'no-store' }); return res.end(); }
        res.writeHead(401, { ...SEC, 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
        return res.end(JSON.stringify({ error: m.error }));
      }
      who = m;
      if (isMeApi) return handleMe(req, res, u, m);
      if (u.pathname === '/me') return sendStatic(req, res, staticText('me.html', ME_HTML), 'text/html; charset=utf-8');
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
    const meta = { n: String(u.searchParams.get('n') || '').replace(/[\u0000-\u001f]/g, ' ').slice(0, 80), k: ['live', 'movie', 'episode'].includes(u.searchParams.get('k')) ? u.searchParams.get('k') : '' };
    if (u.pathname !== '/proxy' || /player_api\.php/i.test(target) || !meta.k) meta.n = meta.k = '';
    const ac = new AbortController();
    conc.set(ip, (conc.get(ip) || 0) + 1);
    if (who) { streamInc(who, res); if (meta.n) trackView(who, meta); }
    let lastB = req.socket.bytesWritten, total = 0;
    const sample = () => { const cur = req.socket.bytesWritten, d = cur - lastB; lastB = cur; if (d > 0) { total += d; if (who) account(who.entry, d / 1e6, meta); } };
    if (who) METERS.add(sample);
    let done = false;
    const release = () => { if (!done) { done = true; const c = (conc.get(ip) || 1) - 1; c ? conc.set(ip, c) : conc.delete(ip); if (who) { streamDec(who, res); sample(); METERS.delete(sample); if (total >= 1e6) console.log('[usage] member=' + who.entry.name + ' MB=' + (total / 1e6).toFixed(1)); } } };
    res.on('close', () => { ac.abort(); release(); });
    try {
      const hd = { 'User-Agent': UA, Accept: '*/*' };
      if (req.headers.range) hd.Range = req.headers.range;
      const listAct = u.pathname === '/proxy' ? listActionOf(target) : '';
      if (listAct) { const hit = listGet(target); if (hit) return sendList(req, res, hit); }
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
      if (listAct && r.statusCode === 200 && !r.headers['content-encoding'] && /json|text/i.test(ct)) {
        const it = r[Symbol.asyncIterator](), chunks = []; let size = 0, streamed = null;
        for (;;) {
          const nx = await it.next(); if (nx.done) break;
          size += nx.value.length;
          if (!streamed && size > LIST_RAW_MAX) {            // too big to keep in memory: compress on the fly instead
            const o = { ...SEC, 'Content-Type': ct, 'Cache-Control': 'no-store', Vary: 'Accept-Encoding' };
            if (acceptsEnc(req, 'gzip')) { o['Content-Encoding'] = 'gzip'; streamed = zlib.createGzip({ level: 4 }); streamed.pipe(res); } else streamed = res;
            res.writeHead(200, o); for (const c of chunks) streamed.write(c); chunks.length = 0;
          }
          if (streamed) { if (!streamed.write(nx.value)) await new Promise(rs => streamed.once('drain', rs)); } else chunks.push(nx.value);
        }
        if (streamed) { streamed.end(); return; }
        const raw = Buffer.concat(chunks);
        const gz = await new Promise(rs => zlib.gzip(raw, { level: 6 }, (e, b) => rs(e ? null : b)));
        if (gz && raw.length > 2 && raw[0] === 0x5b) { const e = { ct: ct || 'application/json', gz, t: Date.now() }; listSet(target, e); return sendList(req, res, e); }
        const o = { ...SEC, 'Content-Type': ct, 'Cache-Control': 'no-store', Vary: 'Accept-Encoding' };
        if (gz && acceptsEnc(req, 'gzip')) { o['Content-Encoding'] = 'gzip'; o['Content-Length'] = gz.length; res.writeHead(200, o); return res.end(gz); }
        o['Content-Length'] = raw.length; res.writeHead(200, o); return res.end(raw);
      }
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
          const body = text.includes('#EXT-X-') ? rewrite(text, r.finalUrl, meta.n ? '&n=' + encodeURIComponent(meta.n) + '&k=' + meta.k : '') : text;
          let buf = Buffer.from(body); const hh = { ...SEC, 'Content-Type': ct || 'application/vnd.apple.mpegurl', 'Cache-Control': 'no-store', Vary: 'Accept-Encoding' };
          if (buf.length > 1024 && acceptsEnc(req, 'gzip')) { const gz = await new Promise(rs => zlib.gzip(buf, { level: 5 }, (e, b) => rs(e ? null : b))); if (gz) { buf = gz; hh['Content-Encoding'] = 'gzip'; } }
          hh['Content-Length'] = buf.length; res.writeHead(r.statusCode, hh);
          return res.end(buf);
        }
        const o = { ...SEC, 'X-Accel-Buffering': 'no', 'Cache-Control': 'no-store' };
        for (const k of ['content-type', 'content-length', 'content-range', 'accept-ranges']) if (r.headers[k]) o[k] = r.headers[k];
        res.writeHead(r.statusCode, o);
        res.write(head);
        r.on('error', () => res.end()); r.pipe(res);
        return;
      }
      if (r.statusCode === 200 && !r.headers['content-range'] && !r.headers['content-encoding'] && /^(application\/json|text\/|application\/(xml|x-mpegurl)|audio\/x-mpegurl)/i.test(ct) && acceptsEnc(req, 'gzip')) {
        res.writeHead(200, { ...SEC, 'Content-Type': ct, 'Content-Encoding': 'gzip', Vary: 'Accept-Encoding', 'Cache-Control': 'no-store', 'X-Accel-Buffering': 'no' });
        const gz = zlib.createGzip({ level: 4 }); r.on('error', () => gz.end()); r.pipe(gz).pipe(res); return;
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

  if (u.pathname === '/app' || /^\/h\/[A-Za-z0-9_-]{6,40}$/.test(u.pathname)) {
    try { return sendStatic(req, res, staticPage('iptv-player.html', h => h.replace('<head>', '<head>\n<script>window.IPTV_PROXY=true</script>')), 'text/html; charset=utf-8'); } catch { return fail(res, 500, 'iptv-player.html not found'); }
  }
  fail(res, 404, 'Not found');
}
server.keepAliveTimeout = 65000; server.headersTimeout = 66000;
server.listen(PORT, '0.0.0.0', () => console.log('IPTV Player listening on :' + PORT + (gateOn() ? ' (access codes: ' + STORE.members.length + ')' : PASS ? ' (password protected)' : ' (NO PASSWORD OR ACCESS CODES SET)')));
