/* ============================================================================
YUVI SDK — Cloudflare Worker (JS, zero-dependency, single file, ALAG ZIP)
- /sdk/mundo/:panel  (AES-128-ECB, dynamic key from salt) — mundo.cpp compatible
- /sdk/bcore/:panel  (RC4 + Base64, key YuviMatrix_Secure_2026) — C++ compatible
- Dashboard: / , /sdk/generate, /sdk/keys, /sdk/server, /sdk/hash (sirf uid=1 OWNER YUVI_001)
Deploy: D1 banao -> schema.sql execute -> DB binding + JWT_SECRET -> worker.js paste -> /setup kholo
============================================================================ */

const SDK_SECRET_KEY = 'YuviMatrix_Secure_2026';
const MUNDO_CLIENT_SALT = 'https://mundo.cp.cheat/v2/api/verify';

// ---------------- AES-128 (ECB, PKCS7) — openssl compatible ----------------
// SBOX/RSBOX runtime-generated (GF(2^8) inverse + affine) — no hardcoded-table typo risk
function _gmul(a, b) { let p = 0; for (let i = 0; i < 8; i++) { if (b & 1) p ^= a; const h = a & 0x80; a = (a << 1) & 0xff; if (h) a ^= 0x1b; b >>= 1; } return p; }
function _ginv(a) { if (!a) return 0; let r = 1, e = 254, x = a; while (e) { if (e & 1) r = _gmul(r, x); x = _gmul(x, x); e >>= 1; } return r; }
const SBOX = new Uint8Array(256), RSBOX = new Uint8Array(256);
for (let _i = 0; _i < 256; _i++) {
  const _v = _ginv(_i);
  const _rot = (v, n) => ((v << n) | (v >> (8 - n))) & 0xff;
  const _s = _v ^ _rot(_v, 1) ^ _rot(_v, 2) ^ _rot(_v, 3) ^ _rot(_v, 4) ^ 0x63;
  SBOX[_i] = _s; RSBOX[_s] = _i;
}
const RCON = [0,1,2,4,8,16,32,64,128,27,54];
function keyExpansion(key) {
  const w = new Uint8Array(176);
  w.set(key, 0);
  for (let i = 4; i < 44; i++) {
    const t = new Uint8Array(4);
    t.set(w.subarray((i - 1) * 4, i * 4));
    if (i % 4 === 0) { const x = t[0]; t[0] = SBOX[t[1]] ^ RCON[i / 4]; t[1] = SBOX[t[2]]; t[2] = SBOX[t[3]]; t[3] = SBOX[x]; }
    for (let k = 0; k < 4; k++) w[i * 4 + k] = w[(i - 4) * 4 + k] ^ t[k];
  }
  return w;
}
function addRK(s, w, r) { for (let i = 0; i < 16; i++) s[i] ^= w[r * 16 + i]; }
function subB(s) { for (let i = 0; i < 16; i++) s[i] = SBOX[s[i]]; }
function invSubB(s) { for (let i = 0; i < 16; i++) s[i] = RSBOX[s[i]]; }
function shiftR(s) { let t; t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t; t = s[2]; s[2] = s[10]; s[10] = t; t = s[6]; s[6] = s[14]; s[14] = t; t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t; }
function invShiftR(s) { let t; t = s[13]; s[13] = s[9]; s[9] = s[5]; s[5] = s[1]; s[1] = t; t = s[10]; s[10] = s[2]; s[2] = t; t = s[14]; s[14] = s[6]; s[6] = t; t = s[3]; s[3] = s[7]; s[7] = s[11]; s[11] = s[15]; s[15] = t; }
function xtime(a) { return ((a << 1) ^ (((a >> 7) & 1) * 0x1b)) & 0xff; }
function mixC(s) { for (let i = 0; i < 16; i += 4) { const a = s[i], b = s[i+1], c = s[i+2], d = s[i+3]; s[i] = xtime(a) ^ xtime(b) ^ b ^ c ^ d; s[i+1] = a ^ xtime(b) ^ xtime(c) ^ c ^ d; s[i+2] = a ^ b ^ xtime(c) ^ xtime(d) ^ d; s[i+3] = xtime(a) ^ a ^ b ^ c ^ xtime(d); } }
function mul(a, b) { let p = 0; for (let i = 0; i < 8; i++) { if (b & 1) p ^= a; const h = a & 0x80; a = (a << 1) & 0xff; if (h) a ^= 0x1b; b >>= 1; } return p; }
function invMixC(s) { for (let i = 0; i < 16; i += 4) { const a = s[i], b = s[i+1], c = s[i+2], d = s[i+3]; s[i] = mul(a,14)^mul(b,11)^mul(c,13)^mul(d,9); s[i+1] = mul(a,9)^mul(b,14)^mul(c,11)^mul(d,13); s[i+2] = mul(a,13)^mul(b,9)^mul(c,14)^mul(d,11); s[i+3] = mul(a,11)^mul(b,13)^mul(c,9)^mul(d,14); } }
function cipherBlk(inp, w) { const s = new Uint8Array(inp); addRK(s, w, 0); for (let r = 1; r < 10; r++) { subB(s); shiftR(s); mixC(s); addRK(s, w, r); } subB(s); shiftR(s); addRK(s, w, 10); return s; }
function invCipherBlk(inp, w) { const s = new Uint8Array(inp); addRK(s, w, 10); for (let r = 9; r >= 1; r--) { invShiftR(s); invSubB(s); addRK(s, w, r); invMixC(s); } invShiftR(s); invSubB(s); addRK(s, w, 0); return s; }
function aesEcbEnc(raw, keyRaw) {
  const w = keyExpansion(keyRaw);
  const pad = 16 - (raw.length % 16);
  const data = new Uint8Array(raw.length + pad).fill(pad); data.set(raw, 0);
  const out = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i += 16) out.set(cipherBlk(data.subarray(i, i + 16), w), i);
  return out;
}
function aesEcbDec(enc, keyRaw) {
  if (enc.length % 16 !== 0 || enc.length === 0) return null;
  const w = keyExpansion(keyRaw);
  const out = new Uint8Array(enc.length);
  for (let i = 0; i < enc.length; i += 16) out.set(invCipherBlk(enc.subarray(i, i + 16), w), i);
  const pad = out[out.length - 1];
  if (pad < 1 || pad > 16) return null;
  for (let i = 0; i < pad; i++) if (out[out.length - 1 - i] !== pad) return null;
  return out.subarray(0, out.length - pad);
}
function mundoRawKey(salt) {
  const L = salt.length, k = new Uint8Array(16);
  for (let i = 0; i < 16; i++) k[i] = (salt.charCodeAt(i % L) ^ ((L + i) & 0xff)) & 0xff;
  return k;
}

// ---------------- RC4 + base64 ----------------
function rc4(data, key) {
  const S = new Uint8Array(256); for (let i = 0; i < 256; i++) S[i] = i;
  let j = 0;
  for (let i = 0; i < 256; i++) { j = (j + S[i] + key[i % key.length]) & 0xff; const t = S[i]; S[i] = S[j]; S[j] = t; }
  let i = 0; j = 0; const out = new Uint8Array(data.length);
  for (let y = 0; y < data.length; y++) { i = (i + 1) & 0xff; j = (j + S[i]) & 0xff; const t = S[i]; S[i] = S[j]; S[j] = t; out[y] = data[y] ^ S[(S[i] + S[j]) & 0xff]; }
  return out;
}
const te = new TextEncoder(), td = new TextDecoder();
function b64e(bytes) { let s = ''; for (const b of bytes) s += String.fromCharCode(b); return btoa(s); }
function b64d(s) { try { const bin = atob(s.trim()); const o = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) o[i] = bin.charCodeAt(i); return o; } catch { return null; } }
// CESU-8 (ED Ax..Bx) -> UTF-8 fix (fancy unicode app labels ke liye, PHP parity)
function cesuFix(bytes) {
  const out = [];
  for (let i = 0; i < bytes.length;) {
    if (i + 5 < bytes.length && bytes[i] === 0xED && bytes[i+1] >= 0xA0 && bytes[i+1] <= 0xAF && bytes[i+3] === 0xED && bytes[i+4] >= 0xB0 && bytes[i+4] <= 0xBF) {
      const h = ((bytes[i+1] & 0x0F) << 6) | (bytes[i+2] & 0x3F);
      const l = ((bytes[i+4] & 0x0F) << 6) | (bytes[i+5] & 0x3F);
      const u = 0x10000 + ((h - 0xD800) << 10) + (l - 0xDC00);
      out.push(0xF0 | ((u >> 18) & 7), 0x80 | ((u >> 12) & 63), 0x80 | ((u >> 6) & 63), 0x80 | (u & 63));
      i += 6;
    } else out.push(bytes[i++]);
  }
  return new Uint8Array(out);
}

// ---------------- auth (PBKDF2 + JWT cookie) ----------------
const esc = (s) => String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
const b64uE = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const b64uD = (s) => { s = s.replace(/-/g,'+').replace(/_/g,'/'); while (s.length % 4) s += '='; return Uint8Array.from(atob(s), c => c.charCodeAt(0)); };
const hexB = (buf) => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2,'0')).join('');
function randHex(n) { const b = new Uint8Array(n); crypto.getRandomValues(b); return [...b].map(x => x.toString(16).padStart(2,'0')).join(''); }
async function hashPw(pw) { const salt = randHex(16); const k = await crypto.subtle.importKey('raw', te.encode(pw), 'PBKDF2', false, ['deriveBits']); const bits = await crypto.subtle.deriveBits({ name:'PBKDF2', salt: te.encode(salt), iterations: 100000, hash:'SHA-256' }, k, 256); return `pbkdf2$100000$${salt}$${hexB(bits)}`; }
async function verifyPw(pw, st) { try { if (!st || st.startsWith('$2')) return false; const [, it, salt, hash] = st.split('$'); const k = await crypto.subtle.importKey('raw', te.encode(pw), 'PBKDF2', false, ['deriveBits']); const bits = await crypto.subtle.deriveBits({ name:'PBKDF2', salt: te.encode(salt), iterations: parseInt(it)||100000, hash:'SHA-256' }, k, 256); return hexB(bits) === hash; } catch { return false; } }
async function jwtSign(p, s) { const h = b64uE(te.encode(JSON.stringify({alg:'HS256',typ:'JWT'}))); const q = b64uE(te.encode(JSON.stringify(p))); const k = await crypto.subtle.importKey('raw', te.encode(s), {name:'HMAC',hash:'SHA-256'}, false, ['sign']); return `${h}.${q}.${b64uE(await crypto.subtle.sign('HMAC',k,te.encode(h+'.'+q)))}`; }
async function jwtVerify(t, s) { try { const [h,p,sg] = t.split('.'); const k = await crypto.subtle.importKey('raw', te.encode(s), {name:'HMAC',hash:'SHA-256'}, false, ['verify']); if (!await crypto.subtle.verify('HMAC',k,b64uD(sg),te.encode(h+'.'+p))) return null; const pl = JSON.parse(new TextDecoder().decode(b64uD(p))); if (pl.exp && Date.now() > pl.exp*1000) return null; return pl; } catch { return null; } }
const ck = (req,n) => { for (const part of (req.headers.get('Cookie')||'').split(';')) { const [k,...v] = part.trim().split('='); if (k===n) return decodeURIComponent(v.join('=')); } return ''; };
const redirect = (u,c) => { const h = new Headers({Location:u}); if (c) h.set('Set-Cookie',c); return new Response(null,{status:302,headers:h}); };
const R = (body,title='YUVI SDK') => new Response(`<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title><script src="https://cdn.tailwindcss.com"></script><link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css"><style>${CSS}</style></head><body>${body}</body></html>`,{headers:{'Content-Type':'text/html; charset=UTF-8'}});
const CSS = `body{font-family:Inter,sans-serif;background:linear-gradient(135deg,#d1fae5,#a7f3d0,#bfdbfe,#d1fae5);background-size:300% 300%;animation:g 18s ease infinite;min-height:100vh;color:#1e293b}@keyframes g{0%{background-position:0% 50%}50%{background-position:100% 50%}100%{background-position:0% 50%}}.glass-card{background:rgba(255,255,255,.8);backdrop-filter:blur(18px);border-radius:20px;border:1px solid rgba(255,255,255,.7);box-shadow:0 4px 20px rgba(6,78,59,.08)}.clay-card{background:linear-gradient(145deg,#fff,#F1F5F9);box-shadow:5px 5px 15px rgba(0,0,0,.05);border-radius:16px;border:1px solid #fff}.btn-premium{width:100%;padding:13px;border-radius:14px;font-weight:800;color:#fff;background:linear-gradient(135deg,#10B981,#059669);border:none;cursor:pointer}.dual-tab-container{display:flex;background:rgba(255,255,255,.6);border-radius:14px;padding:4px;gap:4px}.dual-tab-btn{padding:8px 16px;border-radius:10px;font-size:12px;font-weight:800;border:none;cursor:pointer;color:#64748B}.active-mundo{background:linear-gradient(135deg,#3B82F6,#1D4ED8)!important;color:#fff!important}.active-bcore{background:linear-gradient(135deg,#F59E0B,#D97706)!important;color:#fff!important}.tab-content-panel{display:none}.tab-content-panel.active{display:block}.clay-input{width:100%;background:#F8FAFC;border:1px solid #E2E8F0;border-radius:12px;padding:11px 14px;font-size:14px;outline:none}.nav-glass-item{display:flex;align-items:center;gap:10px;padding:11px 14px;border-radius:14px;text-decoration:none;color:#334155;font-weight:500;margin-bottom:4px}.nav-active{background:linear-gradient(135deg,#10B981,#047857)!important;color:#fff!important;font-weight:700}`;
const switchJS = `<script>function switchDualTab(id,tab){const w=document.getElementById(id);const wrap=w.closest('.dual-tab-wrapper')||document;wrap.querySelectorAll('.dual-tab-btn').forEach(b=>b.classList.remove('active-mundo','active-bcore'));wrap.querySelectorAll('.tab-content-panel').forEach(p=>p.classList.remove('active'));const btn=wrap.querySelector('[data-tab=\"'+tab+'\"]');if(btn)btn.classList.add(tab==='mundo'?'active-mundo':'active-bcore');wrap.querySelectorAll('.tab-content-panel[data-tab=\"'+tab+'\"]').forEach(p=>p.classList.add('active'))}</script>`;

function shell(u, active, content) {
  const items = [['dashboard','/','bi-speedometer2','Dashboard'],['generate','/sdk/generate','bi-key-fill','Generate'],['keys','/sdk/keys','bi-view-list','Keys'],['server','/sdk/server','bi-hdd-network-fill','Server'],['hash','/sdk/hash','bi-shield-check','Hash']];
  const nav = items.map(([k,h,ic,l]) => `<a href="${h}" class="nav-glass-item ${active===k?'nav-active':''}"><i class="bi ${ic}"></i>${l}</a>`).join('');
  return `<div class="flex min-h-screen"><aside class="hidden md:flex flex-col w-60 p-4"><div class="glass-card p-4 mb-3 text-center"><h1 class="font-black text-emerald-700 text-sm">YUVI SDK</h1><p class="text-[11px] text-slate-500">${esc(u.username)}</p></div><nav class="glass-card p-3 flex-1">${nav}<a href="/logout" class="nav-glass-item text-red-500"><i class="bi bi-box-arrow-right"></i>Logout</a></nav></aside><main class="flex-1 p-4 md:p-6 max-w-6xl mx-auto w-full"><div class="md:hidden glass-card p-2 mb-3 flex gap-1 overflow-x-auto text-xs">${items.map(([k,h,ic,l]) => `<a href="${h}" class="px-3 py-2 rounded-lg whitespace-nowrap ${active===k?'bg-emerald-600 text-white font-bold':'text-slate-600'}">${l}</a>`).join('')}</div>${content}</main></div>${switchJS}`;
}
function tabs(id, mCount, bCount) {
  return `<div class="dual-tab-container" id="${id}"><button class="dual-tab-btn active-mundo" data-tab="mundo" onclick="switchDualTab('${id}','mundo')"><i class="bi bi-cpu"></i> MUNDO${mCount!==undefined?` (${mCount})`:''}</button><button class="dual-tab-btn" data-tab="bcore" onclick="switchDualTab('${id}','bcore')"><i class="bi bi-lightning-charge-fill"></i> BCORE${bCount!==undefined?` (${bCount})`:''}</button></div>`;
}

export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    const path = url.pathname.replace(/\/+$/,'') || '/';
    const method = req.method;
    if (method === 'OPTIONS') return new Response(null,{status:204});

    // ---- encrypted game APIs (no cookie auth) ----
    let m = path.match(/^\/sdk\/mundo\/([A-Za-z0-9_-]+)$/);
    if (m && method === 'POST') return apiMundo(req, env, m[1]);
    m = path.match(/^\/sdk\/bcore\/([A-Za-z0-9_-]+)$/);
    if (m && method === 'POST') return apiBcore(req, env, m[1]);
    if (m) return encResp(m[1].includes('mundo') ? 'mundo' : 'bcore', {status:'error',code:'METHOD_NOT_ALLOWED',message:'Only POST method allowed'}, 405);

    if (path === '/setup') {
      await env.DB.prepare('INSERT OR IGNORE INTO panels (panel_code, is_active) VALUES (?,1)').bind('YUVI_001').run();
      const c = await env.DB.prepare('SELECT id FROM users WHERE id = 1').first();
      if (!c) await env.DB.prepare('INSERT INTO users (id, full_name, username, password, role, panel_code) VALUES (1,?,?,?,?,?)').bind('Main Owner','admin', await hashPw('Admin@123'), 'OWNER', 'YUVI_001').run();
      return new Response('SDK setup done. Login: admin / Admin@123',{headers:{'Content-Type':'text/plain'}});
    }
    if (path === '/login') {
      if (method === 'GET') return R(`<div class="min-h-screen flex items-center justify-center p-5"><div class="w-full max-w-[380px]"><div class="glass-card p-6"><h1 class="font-black text-center text-emerald-700 mb-1">YUVI SDK</h1><p class="text-xs text-center text-slate-500 mb-4">Owner login (id=1)</p><form method="POST" class="space-y-3"><input name="username" required class="clay-input" placeholder="Username"><input name="password" type="password" required class="clay-input" placeholder="Password"><button class="btn-premium">Login</button></form></div></div></div>`,'SDK Login');
      const fd = await req.formData();
      const u = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(String(fd.get('username')||'').trim()).first();
      if (!u || !(await verifyPw(String(fd.get('password')||''), u.password))) return R(`<div class="p-10 text-center font-bold text-red-600">Invalid login. <a href="/login" class="underline">Back</a></div>`);
      if (u.is_blocked) return R(`<div class="p-10 text-center font-bold text-red-600">Blocked.</div>`);
      const t = await jwtSign({uid:u.id,exp:Math.floor(Date.now()/1000)+7*86400}, env.JWT_SECRET||'dev-secret');
      return redirect('/', `yuvi_sdk=${encodeURIComponent(t)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800`);
    }
    if (path === '/logout') { const h = new Headers({Location:'/login'}); h.set('Set-Cookie','yuvi_sdk=; Path=/; Max-Age=0'); return new Response(null,{status:302,headers:h}); }

    // ---- dashboard auth: sirf uid 1 OWNER YUVI_001 (PHP parity) ----
    const t = ck(req,'yuvi_sdk');
    const pl = t ? await jwtVerify(t, env.JWT_SECRET||'dev-secret') : null;
    const me = pl ? await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(pl.uid).first() : null;
    if (!me || me.is_blocked) return redirect('/login');
    if (!(me.id === 1 && me.role === 'OWNER' && me.panel_code === 'YUVI_001')) return new Response('<h2 style="text-align:center;margin-top:60px">ACCESS DENIED: Only Main Owner (YUVI_001)</h2>',{status:403,headers:{'Content-Type':'text/html'}});
    const PC = 'YUVI_001';

    if (path === '/') {
      const n = async (sql) => (await env.DB.prepare(sql).bind(PC).first())?.n || 0;
      const mT = await n('SELECT COUNT(*) as n FROM mundo_keys WHERE panel_code = ?');
      const mA = await n('SELECT COUNT(*) as n FROM mundo_keys WHERE panel_code = ? AND is_blocked = 0');
      const bT = await n('SELECT COUNT(*) as n FROM bcore_keys WHERE panel_code = ?');
      const bA = await n('SELECT COUNT(*) as n FROM bcore_keys WHERE panel_code = ? AND is_blocked = 0');
      const mB = (await env.DB.prepare('SELECT COUNT(*) as n FROM mundo_key_bindings b JOIN mundo_keys k ON b.sdk_key_id=k.id WHERE k.panel_code=?').bind(PC).first())?.n || 0;
      const bB = (await env.DB.prepare('SELECT COUNT(*) as n FROM bcore_key_bindings b JOIN bcore_keys k ON b.sdk_key_id=k.id WHERE k.panel_code=?').bind(PC).first())?.n || 0;
      const host = url.host, proto = url.protocol.replace(':','');
      const c = `<div class="dual-tab-wrapper"><div class="flex justify-between items-center mb-4 flex-wrap gap-3"><div><h1 class="text-2xl font-black">SDK Dashboard</h1><p class="text-xs text-slate-500">MUNDO + BCORE overview</p></div>${tabs('dashTabs')}</div>
      <div class="tab-content-panel active" data-tab="mundo"><div class="grid grid-cols-2 lg:grid-cols-4 gap-3"><div class="glass-card p-4"><p class="text-2xl font-black">${mT}</p><p class="text-xs">MUNDO Keys</p></div><div class="glass-card p-4"><p class="text-2xl font-black">${mA}</p><p class="text-xs">Active</p></div><div class="glass-card p-4"><p class="text-2xl font-black">${mT-mA}</p><p class="text-xs">Blocked</p></div><div class="glass-card p-4"><p class="text-2xl font-black">${mB}</p><p class="text-xs">Bindings</p></div></div><div class="glass-card p-4 mt-3 font-mono text-xs break-all">POST ${proto}://${host}/sdk/mundo/${PC}</div></div>
      <div class="tab-content-panel" data-tab="bcore"><div class="grid grid-cols-2 lg:grid-cols-4 gap-3"><div class="glass-card p-4"><p class="text-2xl font-black">${bT}</p><p class="text-xs">BCORE Keys</p></div><div class="glass-card p-4"><p class="text-2xl font-black">${bA}</p><p class="text-xs">Active</p></div><div class="glass-card p-4"><p class="text-2xl font-black">${bT-bA}</p><p class="text-xs">Blocked</p></div><div class="glass-card p-4"><p class="text-2xl font-black">${bB}</p><p class="text-xs">Bindings</p></div></div><div class="glass-card p-4 mt-3 font-mono text-xs break-all">POST ${proto}://${host}/sdk/bcore/${PC}</div></div></div>`;
      return R(shell(me,'dashboard',c),'SDK Dashboard');
    }

    if (path === '/sdk/generate') {
      let msg = '';
      if (method === 'POST') {
        const fd = await req.formData();
        const eng = String(fd.get('engine')||'MUNDO') === 'BCORE' ? 'BCORE' : 'MUNDO';
        let sdkKey = String(fd.get('sdk_key')||'').trim();
        const dur = parseInt(fd.get('duration')) || 30, pl2 = Math.max(1,parseInt(fd.get('pkg_limit'))||1), al = Math.max(1,parseInt(fd.get('app_limit'))||1);
        const f1 = fd.get('feature1') ? 1 : 0, f2 = fd.get('feature2') ? 1 : 0;
        const table = eng === 'BCORE' ? 'bcore_keys' : 'mundo_keys';
        if (sdkKey && sdkKey.length < 5) msg = 'Custom key min 5 chars.';
        else if (![7,15,30,60].includes(dur)) msg = 'Invalid duration.';
        else if (pl2 > 10 || al > 20) msg = 'Limits too high.';
        else {
          if (!sdkKey) sdkKey = randHex(8).toUpperCase();
          const ex = await env.DB.prepare(`SELECT id FROM ${table} WHERE sdk_key = ? AND panel_code = ?`).bind(sdkKey, PC).first();
          if (ex) msg = `Key already exists in ${eng}.`;
          else { await env.DB.prepare(`INSERT INTO ${table} (panel_code, sdk_key, duration_days, pkg_limit, app_limit, feature1, feature2, created_by) VALUES (?,?,?,?,?,?,?,?)`).bind(PC, sdkKey, dur, pl2, al, f1, f2, me.id).run(); msg = `OK: ${eng} | ${sdkKey} (${dur}d, pkg ${pl2}, app ${al})`; }
        }
      }
      const form = (eng) => `<form method="POST" class="glass-card p-5"><input type="hidden" name="engine" value="${eng}"><div class="grid md:grid-cols-2 gap-2"><input name="sdk_key" placeholder="Custom key (empty=auto)" class="clay-input font-mono"><select name="duration" class="clay-input"><option value="7">7 Days</option><option value="15">15 Days</option><option value="30" selected>30 Days</option><option value="60">60 Days</option></select><input name="pkg_limit" type="number" value="1" min="1" max="10" class="clay-input"><input name="app_limit" type="number" value="1" min="1" max="20" class="clay-input"></div><div class="flex gap-4 mt-2 text-sm font-bold"><label><input type="checkbox" name="feature1"> Feature1</label><label><input type="checkbox" name="feature2"> Feature2</label></div><button class="btn-premium mt-3">Generate ${eng}</button></form>`;
      return R(shell(me,'generate',`<div class="dual-tab-wrapper"><div class="flex justify-between items-center mb-4 flex-wrap gap-3"><h1 class="text-2xl font-black">Generate SDK</h1>${tabs('genTabs')}</div>${msg?`<div class="glass-card p-3 mb-3 text-sm font-bold">${esc(msg)}</div>`:''}<div class="tab-content-panel active" data-tab="mundo">${form('MUNDO')}</div><div class="tab-content-panel" data-tab="bcore">${form('BCORE')}</div></div>`),'Generate SDK');
    }

    if (path === '/sdk/keys') {
      if (method === 'POST') {
        const fd = await req.formData();
        const eng = String(fd.get('engine')||'MUNDO') === 'BCORE' ? 'BCORE' : 'MUNDO';
        const kt = eng==='BCORE'?'bcore_keys':'mundo_keys', bt = eng==='BCORE'?'bcore_key_bindings':'mundo_key_bindings';
        const kid = parseInt(fd.get('key_id'))||0, bid = parseInt(fd.get('bind_id'))||0, a = String(fd.get('action')||'');
        const own = await env.DB.prepare(`SELECT id FROM ${kt} WHERE id = ? AND panel_code = ?`).bind(kid, PC).first();
        if (own) {
          if (a==='block_key') await env.DB.prepare(`UPDATE ${kt} SET is_blocked=1 WHERE id=?`).bind(kid).run();
          if (a==='unblock_key') await env.DB.prepare(`UPDATE ${kt} SET is_blocked=0 WHERE id=?`).bind(kid).run();
          if (a==='delete_key') await env.DB.prepare(`DELETE FROM ${kt} WHERE id=?`).bind(kid).run();
          if (a==='block_bind'&&bid) await env.DB.prepare(`UPDATE ${bt} SET is_blocked=1 WHERE id=? AND sdk_key_id=?`).bind(bid,kid).run();
          if (a==='unblock_bind'&&bid) await env.DB.prepare(`UPDATE ${bt} SET is_blocked=0 WHERE id=? AND sdk_key_id=?`).bind(bid,kid).run();
          if (a==='delete_bind'&&bid) await env.DB.prepare(`DELETE FROM ${bt} WHERE id=? AND sdk_key_id=?`).bind(bid,kid).run();
          if (a==='add_bind') {
            const pkg = String(fd.get('pkg_name')||'').trim(), app = String(fd.get('app_name')||'').trim();
            if (pkg && app) {
              const lim = await env.DB.prepare(`SELECT pkg_limit, app_limit FROM ${kt} WHERE id=?`).bind(kid).first();
              const tot = (await env.DB.prepare(`SELECT COUNT(*) as n FROM ${bt} WHERE sdk_key_id=?`).bind(kid).first())?.n||0;
              if (tot < lim.pkg_limit * lim.app_limit) await env.DB.prepare(`INSERT INTO ${bt} (sdk_key_id, pkg_name, app_name) VALUES (?,?,?)`).bind(kid,pkg,app).run();
            }
          }
        }
        return redirect('/sdk/keys');
      }
      const fetchK = async (kt,bt) => { const ks = (await env.DB.prepare(`SELECT * FROM ${kt} WHERE panel_code=? ORDER BY id DESC`).bind(PC).all()).results; for (const k of ks) k.bindings = (await env.DB.prepare(`SELECT * FROM ${bt} WHERE sdk_key_id=? ORDER BY id DESC`).bind(k.id).all()).results; return ks; };
      const mK = await fetchK('mundo_keys','mundo_key_bindings'), bK = await fetchK('bcore_keys','bcore_key_bindings');
      const card = (k, eng) => `<div class="clay-card p-3 mb-2"><div class="flex justify-between items-center gap-2"><div><p class="font-mono font-bold text-sm">${esc(k.sdk_key)}</p><p class="text-[11px] text-slate-500">${k.duration_days}d • pkg ${k.pkg_limit} • app ${k.app_limit} • ${k.is_blocked?'BLOCKED':'ACTIVE'}</p>${k.bindings.map(b=>`<p class="text-[11px] font-mono bg-slate-50 border rounded-lg px-2 py-1 mt-1">${esc(b.pkg_name)} / ${esc(b.app_name)} ${b.is_blocked?'(blocked)':''}</p>`).join('')}</div><div class="flex gap-1 shrink-0"><form method="POST" class="inline"><input type="hidden" name="engine" value="${eng}"><input type="hidden" name="key_id" value="${k.id}"><input type="hidden" name="action" value="${k.is_blocked?'unblock_key':'block_key'}"><button class="px-2 py-1 bg-slate-100 rounded-lg text-xs">⏯</button></form><form method="POST" class="inline"><input type="hidden" name="engine" value="${eng}"><input type="hidden" name="key_id" value="${k.id}"><input type="hidden" name="action" value="delete_key"><button class="px-2 py-1 bg-red-50 text-red-500 rounded-lg text-xs">Del</button></form></div></div><form method="POST" class="flex gap-1 mt-2"><input type="hidden" name="engine" value="${eng}"><input type="hidden" name="key_id" value="${k.id}"><input type="hidden" name="action" value="add_bind"><input name="pkg_name" placeholder="package" class="clay-input" style="padding:6px 10px;font-size:12px"><input name="app_name" placeholder="app" class="clay-input" style="padding:6px 10px;font-size:12px"><button class="px-3 py-1 bg-emerald-500 text-white rounded-lg text-xs font-bold">+Bind</button></form></div>`;
      return R(shell(me,'keys',`<div class="dual-tab-wrapper"><div class="flex justify-between items-center mb-4 flex-wrap gap-3"><h1 class="text-2xl font-black">SDK Keys</h1>${tabs('keysTabs',mK.length,bK.length)}</div><div class="tab-content-panel active" data-tab="mundo">${mK.map(k=>card(k,'MUNDO')).join('')||'<div class="glass-card p-8 text-center text-slate-400 text-sm">No MUNDO keys</div>'}</div><div class="tab-content-panel" data-tab="bcore">${bK.map(k=>card(k,'BCORE')).join('')||'<div class="glass-card p-8 text-center text-slate-400 text-sm">No BCORE keys</div>'}</div></div>`),'SDK Keys');
    }

    if (path === '/sdk/server') {
      if (method === 'POST') {
        const fd = await req.formData();
        const eng = String(fd.get('engine')||'MUNDO')==='BCORE'?'BCORE':'MUNDO';
        await env.DB.prepare('INSERT INTO sdk_server_status (panel_code, engine, maintenance_mode, maintenance_message) VALUES (?,?,?,?) ON CONFLICT(panel_code, engine) DO UPDATE SET maintenance_mode=excluded.maintenance_mode, maintenance_message=excluded.maintenance_message').bind(PC, eng, fd.get('maintenance_mode')?'1':'0', String(fd.get('maintenance_message')||'')).run();
        return redirect('/sdk/server');
      }
      const rows = (await env.DB.prepare('SELECT * FROM sdk_server_status WHERE panel_code=?').bind(PC).all()).results;
      const st = {MUNDO:{m:0,msg:''},BCORE:{m:0,msg:''}};
      for (const r of rows) st[r.engine] = {m:r.maintenance_mode, msg:r.maintenance_message||''};
      const host = url.host, proto = url.protocol.replace(':','');
      const sec = (eng) => `<div class="glass-card p-5 mb-4"><h3 class="font-bold mb-2">${eng} Server ${st[eng].m?'(MAINTENANCE)':'(ONLINE)'}</h3><p class="font-mono text-xs bg-slate-900 text-emerald-300 p-3 rounded-xl break-all mb-3">POST ${proto}://${host}/sdk/${eng.toLowerCase()}/${PC}</p><form method="POST" class="space-y-2"><input type="hidden" name="engine" value="${eng}"><label class="text-sm font-bold"><input type="checkbox" name="maintenance_mode" ${st[eng].m?'checked':''}> Maintenance</label><input name="maintenance_message" value="${esc(st[eng].msg)}" placeholder="Message" class="clay-input"><button class="btn-premium">Save ${eng}</button></form></div>`;
      return R(shell(me,'server',`<div class="dual-tab-wrapper"><div class="flex justify-between items-center mb-4 flex-wrap gap-3"><h1 class="text-2xl font-black">Server & API</h1>${tabs('srvTabs')}</div><div class="tab-content-panel active" data-tab="mundo">${sec('MUNDO')}</div><div class="tab-content-panel" data-tab="bcore">${sec('BCORE')}</div></div>`),'Server & API');
    }

    if (path === '/sdk/hash') {
      if (method === 'POST') {
        const fd = await req.formData();
        const a = String(fd.get('action')||''), eng = String(fd.get('engine')||'MUNDO')==='BCORE'?'BCORE':'MUNDO';
        if (a==='add_hash') {
          const label = String(fd.get('hash_label')||'').slice(0,100), val = String(fd.get('hash_value')||'').toLowerCase().trim();
          if (/^[a-f0-9]{64}$/.test(val)) await env.DB.prepare('INSERT INTO sdk_hash_vault (panel_code, engine, hash_type, hash_label, hash_value) VALUES (?,?,?,?,?)').bind(PC, eng, 'lib_signature', label, val).run();
        }
        if (a==='toggle_hash') { const id = parseInt(fd.get('hash_id'))||0; await env.DB.prepare('UPDATE sdk_hash_vault SET is_active = 1 - is_active WHERE id=? AND panel_code=?').bind(id,PC).run(); }
        if (a==='delete_hash') { const id = parseInt(fd.get('hash_id'))||0; await env.DB.prepare('DELETE FROM sdk_hash_vault WHERE id=? AND panel_code=?').bind(id,PC).run(); }
        return redirect('/sdk/hash');
      }
      const hashes = (await env.DB.prepare('SELECT * FROM sdk_hash_vault WHERE panel_code=? ORDER BY id DESC').bind(PC).all()).results;
      const aesHex = [...mundoRawKey(MUNDO_CLIENT_SALT)].map(b=>b.toString(16).padStart(2,'0')).join('');
      const sec = (eng) => { const list = hashes.filter(h=>h.engine===eng); return `<div class="glass-card p-5 mb-4"><h3 class="font-bold mb-3">Add ${eng} Lib Hash (SHA-256)</h3><form method="POST" class="grid md:grid-cols-2 gap-2"><input type="hidden" name="action" value="add_hash"><input type="hidden" name="engine" value="${eng}"><input name="hash_label" required placeholder="Label (libxxx.so)" class="clay-input font-mono text-xs"><input name="hash_value" required pattern="[a-fA-F0-9]{64}" placeholder="64 hex" class="clay-input font-mono text-xs"><button class="btn-premium md:col-span-2">Add Hash</button></form><div class="mt-3 space-y-2">${list.map(h=>`<div class="clay-card p-2 flex justify-between items-center gap-2"><div class="min-w-0"><p class="text-xs font-bold">${esc(h.hash_label)} ${h.is_active?'• ACTIVE':'• OFF'}</p><p class="text-[10px] font-mono text-slate-500 break-all">${esc(h.hash_value)}</p></div><span class="flex gap-1 shrink-0"><form method="POST" class="inline"><input type="hidden" name="action" value="toggle_hash"><input type="hidden" name="engine" value="${eng}"><input type="hidden" name="hash_id" value="${h.id}"><button class="px-2 py-1 bg-slate-100 rounded-lg text-xs">⏯</button></form><form method="POST" class="inline"><input type="hidden" name="action" value="delete_hash"><input type="hidden" name="engine" value="${eng}"><input type="hidden" name="hash_id" value="${h.id}"><button class="px-2 py-1 bg-red-50 text-red-500 rounded-lg text-xs">Del</button></form></span></div>`).join('')||'<p class="text-xs text-slate-400">No hashes</p>'}</div></div>`; };
      return R(shell(me,'hash',`<div class="dual-tab-wrapper"><div class="flex justify-between items-center mb-4 flex-wrap gap-3"><h1 class="text-2xl font-black">Lib Hash Vault</h1>${tabs('hashTabs')}</div><div class="glass-card p-4 mb-4 text-xs font-mono break-all">SALT: ${esc(MUNDO_CLIENT_SALT)}<br>AES-128: ${aesHex}</div><div class="tab-content-panel active" data-tab="mundo">${sec('MUNDO')}</div><div class="tab-content-panel" data-tab="bcore">${sec('BCORE')}</div></div>`),'Hash Vault');
    }

    return new Response('404',{status:404});
  }
};

// ---------------- encrypted responders ----------------
function encResp(engine, obj, code=200) {
  if (engine === 'bcore') {
    const enc = b64e(rc4(te.encode(JSON.stringify(obj)), te.encode(SDK_SECRET_KEY)));
    return new Response(enc,{status:code,headers:{'Content-Type':'text/plain; charset=UTF-8','Cache-Control':'no-store'}});
  }
  const k = mundoRawKey(MUNDO_CLIENT_SALT);
  const enc = b64e(aesEcbEnc(te.encode(JSON.stringify(obj)), k));
  return new Response(enc,{status:code,headers:{'Content-Type':'text/plain; charset=UTF-8','Cache-Control':'no-store'}});
}

async function apiBcore(req, env, panel_code) {
  const need = (o,c) => encResp('bcore',o,c);
  const p = await env.DB.prepare('SELECT panel_code FROM panels WHERE panel_code=?').bind(panel_code).first();
  if (!p) return need({status:'error',code:'INVALID_PANEL',message:'Panel not found'},404);
  const raw = (await req.text()).trim();
  if (!raw) return need({status:'error',code:'EMPTY_BODY',message:'Request body is empty'},400);
  const dec = cesuFix(rc4(b64d(raw) || new Uint8Array(0), te.encode(SDK_SECRET_KEY)));
  let input = null;
  try { input = JSON.parse(td.decode(dec)); } catch { try { input = Object.fromEntries(new URLSearchParams(td.decode(dec))); } catch {} }
  if (!input || !input.sdk_key) return need({status:'error',code:'DECRYPT_FAILED',message:'Invalid encrypted payload'},400);
  const sdk_key = String(input.sdk_key||input.user_key||'').trim(), pkg = String(input.pkg_name||input.package_name||'').trim(), app = String(input.app_name||'').trim(), dev = String(input.device_id||'').trim();
  const mst = await env.DB.prepare("SELECT maintenance_mode, maintenance_message FROM sdk_server_status WHERE panel_code=? AND engine='BCORE'").bind(panel_code).first().catch(()=>null);
  if (mst && +mst.maintenance_mode === 1) return need({status:'error',code:'SERVER_MAINTENANCE',message:mst.maintenance_message||'Server is under maintenance'},503);
  for (const [nm,v] of [['sdk_key',sdk_key],['pkg_name',pkg],['app_name',app]]) if (!v) return need({status:'error',code:'MISSING_PARAMETER',message:'Required parameter is missing',parameter:nm},400);
  const key = await env.DB.prepare('SELECT * FROM bcore_keys WHERE sdk_key=? AND panel_code=?').bind(sdk_key,panel_code).first().catch(()=>null);
  if (!key) return need({status:'error',code:'INVALID_KEY',message:'Invalid SDK key'},400);
  if (+key.is_blocked === 1) return need({status:'error',code:'INVALID_KEY',message:'Invalid SDK key'},403);
  if (Date.now() > new Date(key.created_at.replace(' ','T')+'Z').getTime() + (+key.duration_days)*864e5) return need({status:'error',code:'EXPIRED_KEY',message:'SDK key has expired'},403);
  const binds = (await env.DB.prepare('SELECT * FROM bcore_key_bindings WHERE sdk_key_id=?').bind(key.id).all()).results;
  const pkgs = [...new Set(binds.map(b=>b.pkg_name))];
  if (!pkgs.includes(pkg) && pkgs.length >= +key.pkg_limit) return need({status:'error',code:'PKG_LIMIT_REACHED',message:'Package limit reached'},403);
  let matched = binds.find(b=>b.pkg_name===pkg && b.app_name===app);
  if (!matched) {
    if (binds.length >= (+key.pkg_limit)*(+key.app_limit)) return need({status:'error',code:'APP_LIMIT_REACHED',message:'App name limit reached'},403);
    if (binds.filter(b=>b.pkg_name===pkg).length >= +key.app_limit) return need({status:'error',code:'APP_LIMIT_REACHED',message:'App name limit reached'},403);
    await env.DB.prepare('INSERT INTO bcore_key_bindings (sdk_key_id, pkg_name, app_name) VALUES (?,?,?)').bind(key.id,pkg,app).run();
    matched = {is_blocked:0};
  }
  if (+matched.is_blocked === 1) return need({status:'error',code:'INVALID_KEY',message:'This app binding is blocked'},403);
  const f1 = +key.feature1===1, f2 = +key.feature2===1;
  return need({status:'success',code:'VALID',message:'SDK key validated successfully',feature1:f1?1:0,feature2:f2?1:0,data:{sdk_key:'valid',pkg_name:pkg,app_name:app,device_id:dev?'registered':null,features1:f1,features2:f2}},200);
}

async function apiMundo(req, env, panel_code) {
  const need = (o,c) => encResp('mundo',o,c);
  const k = mundoRawKey(MUNDO_CLIENT_SALT);
  const p = await env.DB.prepare('SELECT panel_code FROM panels WHERE panel_code=?').bind(panel_code).first();
  if (!p) return need({status:false,code:'error',message:'Panel not found'},404);
  const raw = (await req.text()).trim();
  if (!raw) return need({status:false,code:'error',message:'Empty body'},400);
  let payload = raw;
  try { const ps = new URLSearchParams(raw); if (ps.get('data')) payload = ps.get('data'); } catch {}
  const eb = b64d(payload);
  if (!eb) return need({status:false,code:'error',message:'Decryption failed'},400);
  const dec = aesEcbDec(eb, k);
  if (!dec) return need({status:false,code:'error',message:'Decryption failed'},400);
  const parts = td.decode(dec).split('|');
  if (parts.length < 4) return need({status:false,code:'error',message:'Malformed payload'},400);
  const [S1,S2,S3A,S3B] = parts;
  const all = (await env.DB.prepare('SELECT * FROM mundo_keys WHERE panel_code=?').bind(panel_code).all()).results;
  let key = null, hwid = '';
  for (const kk of all) { if (S1.startsWith(kk.sdk_key)) { key = kk; hwid = S1.slice(kk.sdk_key.length); break; } }
  if (!key) return need({status:false,code:'error',message:'Invalid SDK key'},403);
  let pkg = '';
  if (S2.endsWith(S1)) { const pre = S2.slice(0, -S1.length); if (pre.length % 2 === 0 && pre.slice(0,pre.length/2) === pre.slice(pre.length/2)) pkg = pre.slice(0,pre.length/2); }
  let app = '';
  if (S3A.endsWith(key.sdk_key)) { const pre = S3A.slice(0, -key.sdk_key.length); if (pre.length % 2 === 0 && pre.slice(0,pre.length/2) === pre.slice(pre.length/2)) app = pre.slice(0,pre.length/2); }
  if (!pkg || !app) return need({status:false,code:'error',message:'Malformed pkg/app'},400);
  const mst = await env.DB.prepare("SELECT maintenance_mode, maintenance_message FROM sdk_server_status WHERE panel_code=? AND engine='MUNDO'").bind(panel_code).first().catch(()=>null);
  if (mst && +mst.maintenance_mode === 1) return need({status:false,code:'error',message:mst.maintenance_message||'Server is under maintenance'},503);
  if (+key.is_blocked === 1) return need({status:false,code:'error',message:'SDK key blocked'},403);
  if (Date.now() > new Date(key.created_at.replace(' ','T')+'Z').getTime() + (+key.duration_days)*864e5) return need({status:false,code:'error',message:'SDK key expired'},403);
  const binds = (await env.DB.prepare('SELECT * FROM mundo_key_bindings WHERE sdk_key_id=?').bind(key.id).all()).results;
  const pkgs = [...new Set(binds.map(b=>b.pkg_name))];
  if (!pkgs.includes(pkg) && pkgs.length >= +key.pkg_limit) return need({status:false,code:'error',message:'Package limit reached'},403);
  let matched = binds.find(b=>b.pkg_name===pkg && b.app_name===app);
  if (!matched) {
    if (binds.length >= (+key.pkg_limit)*(+key.app_limit)) return need({status:false,code:'error',message:'App limit reached'},403);
    if (binds.filter(b=>b.pkg_name===pkg).length >= +key.app_limit) return need({status:false,code:'error',message:'App limit reached'},403);
    await env.DB.prepare('INSERT INTO mundo_key_bindings (sdk_key_id, pkg_name, app_name) VALUES (?,?,?)').bind(key.id,pkg,app).run();
    matched = {is_blocked:0};
  }
  if (+matched.is_blocked === 1) return need({status:false,code:'error',message:'Binding blocked'},403);
  return encResp('mundo',{status:true,code:'success',message:'SDK key validated',pkg_name:pkg,app_name:app,hwid,feature1:+key.feature1,feature2:+key.feature2},200);
}
