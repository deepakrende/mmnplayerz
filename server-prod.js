// IPTV Player: production server (Node 18+). Serves the player and a hardened stream proxy.
// Env: PORT, ACCESS_PASSWORD, TRUST_PROXY=1 (Caddy/nginx) or render, RATE_LIMIT, MAX_STREAMS_PER_IP, ALLOW_INSECURE_TLS=1
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
function authed(req) {
  if (!PASS) return true;
  const m = /^Basic (.+)$/.exec(req.headers.authorization || '');
  if (!m) return false;
  const given = Buffer.from(m[1], 'base64').toString().split(':').slice(1).join(':');
  const a = crypto.createHash('sha256').update(given).digest(), b = crypto.createHash('sha256').update(PASS).digest();
  return crypto.timingSafeEqual(a, b);
}
const fail = (res, code, msg) => { if (!res.headersSent) res.writeHead(code, { ...SEC, 'Content-Type': 'text/plain' }); res.end(msg); };

const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, 'http://localhost');
  if (u.pathname === '/healthz') return fail(res, 200, 'ok');
  if (u.pathname === '/' || u.pathname === '/index.html') {
    try {
      res.writeHead(200, { ...SEC, 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache' });
      return res.end(fs.readFileSync(path.join(__dirname, 'landing.html')));
    } catch { return fail(res, 500, 'landing.html not found'); }
  }
  if (!authed(req)) { res.writeHead(401, { ...SEC, 'WWW-Authenticate': 'Basic realm="IPTV Player"' }); return res.end('Password required'); }

  if (u.pathname === '/proxy' || u.pathname === '/diag') {
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
      if (/mpegurl/i.test(ct) || /\.m3u8?$/i.test(new URL(r.finalUrl).pathname)) {
        const chunks = []; let size = 0;
        for await (const c of r) { size += c.length; if (size > MAX_PLAYLIST) { r.destroy(); return fail(res, 502, 'Playlist too large'); } chunks.push(c); }
        const text = Buffer.concat(chunks).toString('utf8');
        const body = text.includes('#EXT-X-') ? rewrite(text, r.finalUrl) : text;
        res.writeHead(r.statusCode, { ...SEC, 'Content-Type': ct || 'application/vnd.apple.mpegurl', 'Cache-Control': 'no-store' });
        return res.end(body);
      }
      const out = { ...SEC, 'X-Accel-Buffering': 'no', 'Cache-Control': 'no-store' };
      for (const k of ['content-type', 'content-length', 'content-range', 'accept-ranges']) if (r.headers[k]) out[k] = r.headers[k];
      res.writeHead(r.statusCode, out);
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
server.listen(PORT, '0.0.0.0', () => console.log('IPTV Player listening on :' + PORT + (PASS ? ' (password protected)' : ' (NO PASSWORD SET)')));
