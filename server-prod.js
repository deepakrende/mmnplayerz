// IPTV Player: production server (Node 18+). Serves the player and a hardened stream proxy.
// Env: PORT, ACCESS_PASSWORD, TRUST_PROXY=1 (Caddy/nginx) or render, RATE_LIMIT, MAX_STREAMS_PER_IP, ALLOW_INSECURE_TLS=1
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
  "frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
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
    signal.addEventListener('abort', () => req.destroy());
    req.end();
  });
}
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
/* ---- sign-in: signed cookie, no database. Changing ACCESS_PASSWORD signs everyone out. ---- */
const SECRET = crypto.createHash('sha256').update('mmn-session:' + PASS).digest();
const SESSION_DAYS = 30;
const sha = v => crypto.createHash('sha256').update(v).digest();
const sign = v => crypto.createHmac('sha256', SECRET).update(v).digest('base64url');
const makeToken = () => { const exp = Date.now() + SESSION_DAYS * 864e5; return exp + '.' + sign(String(exp)); };
function validToken(t) {
  const i = (t || '').indexOf('.'); if (i < 1) return false;
  const exp = t.slice(0, i), sig = t.slice(i + 1);
  if (!(+exp > Date.now())) return false;
  const x = Buffer.from(sig), y = Buffer.from(sign(exp));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}
const cookies = req => Object.fromEntries((req.headers.cookie || '').split(/;\s*/).filter(Boolean).map(c => { const i = c.indexOf('='); return [c.slice(0, i), c.slice(i + 1)]; }));
function authed(req) {
  if (!PASS) return true;
  if (validToken(cookies(req).mmn_session)) return true;
  const m = /^Basic (.+)$/.exec(req.headers.authorization || '');   // still accepted for scripts / curl
  if (!m) return false;
  return crypto.timingSafeEqual(sha(Buffer.from(m[1], 'base64').toString().split(':').slice(1).join(':')), sha(PASS));
}
const isHttps = req => !!TRUST_MODE && /https/i.test(req.headers['x-forwarded-proto'] || '');
const setCookie = (req, val, maxAge) => 'mmn_session=' + val + '; Path=/; HttpOnly; SameSite=Lax; Max-Age=' + maxAge + (isHttps(req) ? '; Secure' : '');
const hostOf = req => String((TRUST_MODE && req.headers['x-forwarded-host']) || req.headers.host || 'localhost').replace(/[^a-zA-Z0-9.:\-\[\]]/g, '');
const originOf = req => (isHttps(req) ? 'https://' : 'http://') + hostOf(req);
const tries = new Map();
setInterval(() => { const n = Date.now(); for (const [k, v] of tries) if (v.reset < n) tries.delete(k); }, 60000).unref();
const readBody = (req, max = 2048) => new Promise((ok, bad) => { let b = ''; req.on('data', c => { b += c; if (b.length > max) { req.destroy(); bad(new Error('big')); } }); req.on('end', () => ok(b)); req.on('error', bad); });

/* ---- static files: read once, compressed once, ETag + caching ---- */
const file = n => { try { return fs.readFileSync(path.join(__dirname, n)); } catch { return null; } };
function prep(buf, type, cc, q = 9) {
  const z = /text|svg|json|manifest|xml/.test(type);
  return { type, cc, raw: buf, gz: z ? zlib.gzipSync(buf, { level: 9 }) : null,
    br: z ? zlib.brotliCompressSync(buf, { params: { [zlib.constants.BROTLI_PARAM_QUALITY]: q } }) : null,
    etag: '"' + crypto.createHash('sha1').update(buf).digest('base64url').slice(0, 20) + '"' };
}
function send(req, res, a, extra = {}, status = 200) {
  const ae = req.headers['accept-encoding'] || '';
  let body = a.raw, enc = '';
  if (a.br && /\bbr\b/.test(ae)) { body = a.br; enc = 'br'; } else if (a.gz && /\bgzip\b/.test(ae)) { body = a.gz; enc = 'gzip'; }
  const h = { ...SEC, 'Content-Type': a.type, 'Cache-Control': a.cc, ETag: a.etag.slice(0, -1) + (enc ? '-' + enc : '') + '"', Vary: 'Accept-Encoding', ...extra };
  if (enc) h['Content-Encoding'] = enc;
  if (status === 200 && req.headers['if-none-match'] === h.ETag) { res.writeHead(304, h); return res.end(); }
  h['Content-Length'] = body.length;
  res.writeHead(status, h); res.end(req.method === 'HEAD' ? undefined : body);
}
const ASSETS = {
  '/favicon.svg': ['favicon.svg', 'image/svg+xml', 'public, max-age=604800'],
  '/apple-touch-icon.png': ['apple-touch-icon.png', 'image/png', 'public, max-age=604800'],
  '/icon-192.png': ['icon-192.png', 'image/png', 'public, max-age=604800'],
  '/icon-512.png': ['icon-512.png', 'image/png', 'public, max-age=604800'],
  '/og.png': ['og.png', 'image/png', 'public, max-age=86400'],
  '/manifest.webmanifest': ['manifest.webmanifest', 'application/manifest+json', 'public, max-age=86400'],
  '/robots.txt': ['robots.txt', 'text/plain; charset=utf-8', 'public, max-age=86400'],
};
const assets = new Map();
for (const [url, [n, type, cc]] of Object.entries(ASSETS)) { const b = file(n); if (b) assets.set(url, prep(b, type, cc)); }
const HTML = 'text/html; charset=utf-8';
const landingRaw = file('landing.html'), loginRaw = file('login.html'), playerRaw = file('iptv-player.html');
const player = playerRaw && prep(Buffer.from(playerRaw.toString('utf8').replace('<head>', '<head>\n<script>window.IPTV_PROXY=true' + (PASS ? ';window.IPTV_AUTH=true' : '') + '</script>')), HTML, 'private, no-cache');
const landingCache = new Map();
const landingFor = o => {
  let a = landingCache.get(o);
  if (!a && landingRaw) { if (landingCache.size > 20) landingCache.clear(); a = prep(Buffer.from(landingRaw.toString('utf8').replace(/\{\{ORIGIN\}\}/g, o)), HTML, 'no-cache'); landingCache.set(o, a); }
  return a;
};
const loginPage = err => prep(Buffer.from(loginRaw.toString('utf8').replace('{{ERROR}}', err ? '<p class="err" role="alert">' + err + '</p>' : '')), HTML, 'no-store', 4);
const NOINDEX = { 'X-Robots-Tag': 'noindex' };
const fail = (res, code, msg) => { if (!res.headersSent) res.writeHead(code, { ...SEC, 'Content-Type': 'text/plain' }); res.end(msg); };

const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, 'http://localhost'), p = u.pathname;
  if (p === '/healthz') return fail(res, 200, 'ok');
  if (assets.has(p)) return send(req, res, assets.get(p));
  if (p === '/' || p === '/index.html') { const a = landingFor(originOf(req)); return a ? send(req, res, a) : fail(res, 500, 'landing.html not found'); }

  if (p === '/login') {
    if (!PASS || authed(req)) { res.writeHead(302, { Location: '/app' }); return res.end(); }
    if (!loginRaw) return fail(res, 500, 'login.html not found');
    if (req.method === 'POST') {
      const o = req.headers.origin;
      if (o) { try { if (new URL(o).host !== hostOf(req)) return fail(res, 403, 'Bad origin'); } catch { return fail(res, 403, 'Bad origin'); } }
      const ip = clientIp(req), now = Date.now();
      let t = tries.get(ip); if (!t || t.reset < now) { t = { n: 0, reset: now + 600000 }; tries.set(ip, t); }
      if (++t.n > 8) return send(req, res, loginPage('Too many attempts. Please wait 10 minutes and try again.'), NOINDEX, 429);
      let body = ''; try { body = await readBody(req); } catch { return fail(res, 413, 'Too large'); }
      if (crypto.timingSafeEqual(sha(new URLSearchParams(body).get('password') || ''), sha(PASS))) {
        tries.delete(ip);
        res.writeHead(303, { Location: '/app', 'Set-Cookie': setCookie(req, makeToken(), SESSION_DAYS * 86400), 'Cache-Control': 'no-store' });
        return res.end();
      }
      return send(req, res, loginPage('That password is not correct.'), NOINDEX, 401);
    }
    return send(req, res, loginPage(''), NOINDEX);
  }
  if (p === '/logout') { res.writeHead(303, { Location: '/', 'Set-Cookie': setCookie(req, '', 0), 'Cache-Control': 'no-store' }); return res.end(); }

  if (!authed(req)) {
    if (p === '/app') { res.writeHead(302, { Location: '/login' }); return res.end(); }
    return fail(res, 401, 'Sign in required');
  }

  if (p === '/proxy' || p === '/diag') {
    if (req.method !== 'GET') return fail(res, 405, 'GET only');
    req.socket.setNoDelay(true);
    const site = req.headers['sec-fetch-site'];
    if (site && site !== 'same-origin') return fail(res, 403, 'Same-origin requests only');
    const ip = clientIp(req), now = Date.now();
    let h = hits.get(ip); if (!h || h.reset < now) { h = { n: 0, reset: now + 60000 }; hits.set(ip, h); }
    if (++h.n > RATE) return fail(res, 429, 'Too many requests');
    if ((conc.get(ip) || 0) >= MAX_CONC) return fail(res, 429, 'Too many open streams');
    const target = u.searchParams.get('u') || '';
    const ac = new AbortController();
    conc.set(ip, (conc.get(ip) || 0) + 1);
    let done = false;
    const release = () => { if (!done) { done = true; const c = (conc.get(ip) || 1) - 1; c ? conc.set(ip, c) : conc.delete(ip); } };
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
        // Some Xtream panels answer ".m3u8" with an endless MPEG-TS stream, so decide from the first bytes:
        // a real playlist starts with #EXTM3U (buffer + rewrite it); anything else is streamed straight through.
        const o = { ...SEC, 'X-Accel-Buffering': 'no', 'Cache-Control': 'no-store' };
        for (const k of ['content-type', 'content-length', 'content-range', 'accept-ranges']) if (r.headers[k]) o[k] = r.headers[k];
        await new Promise(resolve => {
          let mode = null, size = 0; const chunks = [];
          r.on('error', () => { if (mode === 'stream') res.end(); else if (!res.headersSent) fail(res, 502, 'Proxy error: upstream failed'); resolve(); });
          r.on('data', c => {
            if (mode === null) {
              mode = /^\uFEFF?\s*#EXTM3U/.test(c.toString('utf8', 0, 32)) ? 'pl' : 'stream';
              if (mode === 'stream') res.writeHead(r.statusCode, o);
            }
            if (mode === 'pl') { size += c.length; if (size > MAX_PLAYLIST) r.destroy(); else chunks.push(c); }
            else if (!res.write(c)) { r.pause(); res.once('drain', () => r.resume()); }
          });
          r.on('end', () => {
            if (mode === 'stream') res.end();
            else {
              const text = Buffer.concat(chunks).toString('utf8');
              const body = text.includes('#EXT-X-') ? rewrite(text, r.finalUrl) : text;
              res.writeHead(r.statusCode, { ...SEC, 'Content-Type': ct || 'application/vnd.apple.mpegurl', 'Cache-Control': 'no-store' });
              res.end(body);
            }
            resolve();
          });
          r.on('close', () => {
            if (!res.writableEnded) { if (mode === 'pl' && size > MAX_PLAYLIST) fail(res, 502, 'Playlist too large'); else res.end(); }
            resolve();
          });
        });
        return;
      }
      const out = { ...SEC, 'X-Accel-Buffering': 'no', 'Cache-Control': 'no-store' };
      for (const k of ['content-type', 'content-length', 'content-range', 'accept-ranges']) if (r.headers[k]) out[k] = r.headers[k];
      res.writeHead(r.statusCode, out);
      r.on('error', () => res.end()); r.pipe(res);
    } catch (e) { fail(res, 502, 'Proxy error: ' + e.message); }
    return;
  }

  if (p === '/app') return player ? send(req, res, player, NOINDEX) : fail(res, 500, 'iptv-player.html not found');
  fail(res, 404, 'Not found');
});
server.keepAliveTimeout = 65000; server.headersTimeout = 66000;
server.listen(PORT, '0.0.0.0', () => console.log('IPTV Player listening on :' + PORT + (PASS ? ' (password protected)' : ' (NO PASSWORD SET)')));
