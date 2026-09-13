/* ===========================================================
   两颗心 LiangKeXin · 情侣实时定位
   - 地图：高德瓦片（GCJ-02 火星坐标系，需实时纠偏）
   - 通道：ntfy.sh 公共中继 + AES-GCM 端到端加密
   - 本地：Leaflet + 原生 JS，零依赖
   =========================================================== */
(function () {
'use strict';

const NTFY = 'https://ntfy.sh';
const $  = s => document.querySelector(s);
const $$ = s => Array.from(document.querySelectorAll(s));

/* ============ 1. 坐标系纠偏 (WGS84 <-> GCJ02) ============ */
const GCJ = (function () {
  const PI = Math.PI, A = 6378245.0, EE = 0.00669342162296594323;
  function outOfChina(lat, lng) { return !(lng > 73.66 && lng < 135.05 && lat > 3.86 && lat < 53.55); }
  function tLat(x, y) {
    let r = -100 + 2 * x + 3 * y + 0.2 * y * y + 0.1 * x * y + 0.2 * Math.sqrt(Math.abs(x));
    r += (20 * Math.sin(6 * x * PI) + 20 * Math.sin(2 * x * PI)) * 2 / 3;
    r += (20 * Math.sin(y * PI) + 40 * Math.sin(y / 3 * PI)) * 2 / 3;
    r += (160 * Math.sin(y / 12 * PI) + 320 * Math.sin(y * PI / 30)) * 2 / 3;
    return r;
  }
  function tLng(x, y) {
    let r = 300 + x + 2 * y + 0.1 * x * x + 0.1 * x * y + 0.1 * Math.sqrt(Math.abs(x));
    r += (20 * Math.sin(6 * x * PI) + 20 * Math.sin(2 * x * PI)) * 2 / 3;
    r += (20 * Math.sin(x * PI) + 40 * Math.sin(x / 3 * PI)) * 2 / 3;
    r += (150 * Math.sin(x / 12 * PI) + 300 * Math.sin(x / 30 * PI)) * 2 / 3;
    return r;
  }
  function delta(lat, lng) {
    let dLat = tLat(lng - 105, lat - 35), dLng = tLng(lng - 105, lat - 35);
    const rad = lat / 180 * PI, m = Math.sin(rad);
    let magic = 1 - EE * m * m, sq = Math.sqrt(magic);
    dLat = (dLat * 180) / ((A * (1 - EE)) / (magic * sq) * PI);
    dLng = (dLng * 180) / (A / sq * Math.cos(rad) * PI);
    return [dLat, dLng];
  }
  return {
    wgs2gcj(lat, lng) {
      if (outOfChina(lat, lng)) return [lat, lng];
      const d = delta(lat, lng);
      return [lat + d[0], lng + d[1]];
    },
    gcj2wgs(lat, lng) {
      if (outOfChina(lat, lng)) return [lat, lng];
      const d = delta(lat, lng);
      return [lat - d[0], lng - d[1]];
    },
    ok(lat, lng) { return typeof lat === 'number' && typeof lng === 'number' &&
      isFinite(lat) && isFinite(lng) && Math.abs(lat) <= 90 && Math.abs(lng) <= 180; }
  };
})();

/* ============ 2. 端到端加密 ============ */
/* 暗号 → ntfy 频道名
   ntfy 只接受 [-_A-Za-z0-9]{1,64}，中文/空格/emoji 暗号会返回 404 且前端毫无提示。
   已合法的暗号原样沿用（保持兼容），其余按 UTF-8 字节折成 128 位确定值。 */
function topicOf(s) {
  s = String(s || '').trim();
  if (!s) return '';
  if (/^[-_A-Za-z0-9]{1,64}$/.test(s)) return s;
  const b = new TextEncoder().encode(s);
  let a = 0x811c9dc5, c = 0x01000193, d = 0x9e3779b9, e = 0x85ebca6b;
  for (let i = 0; i < b.length; i++) {
    a = Math.imul(a ^ b[i], 0x01000193) >>> 0;
    c = Math.imul(c + b[i] + i, 0x85ebca6b) >>> 0;
    d = Math.imul(d ^ (b[i] + i), 0xc2b2ae35) >>> 0;
    e = ((Math.imul(e + b[i], 0x27d4eb2f) >>> 0) ^ (a >>> 7)) >>> 0;
  }
  const p = x => ('0000000' + (x >>> 0).toString(36)).slice(-7);
  return 'lk' + p(a) + p(c) + p(d) + p(e);
}

const Crypto_ = (function () {
  let cacheKey = null, cachePass = '';
  async function key(pass) {
    if (cachePass === pass && cacheKey) return cacheKey;
    const enc = new TextEncoder();
    const base = await crypto.subtle.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveKey']);
    cacheKey = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: enc.encode('liangkeixin-salt-v1'), iterations: 60000, hash: 'SHA-256' },
      base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    cachePass = pass;
    return cacheKey;
  }
  const b64 = buf => btoa(String.fromCharCode.apply(null, new Uint8Array(buf)));
  const raw = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  return {
    on: !!(window.crypto && crypto.subtle),
    async enc(text, pass) {
      const k = await key(pass), iv = crypto.getRandomValues(new Uint8Array(12));
      const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, k, new TextEncoder().encode(text));
      const all = new Uint8Array(iv.length + ct.byteLength);
      all.set(iv, 0); all.set(new Uint8Array(ct), iv.length);
      return 'E1:' + b64(all);
    },
    async dec(payload, pass) {
      if (payload.indexOf('E1:') !== 0) return payload;
      const buf = raw(payload.slice(3));
      const k = await key(pass);
      const pt = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: buf.slice(0, 12) }, k, buf.slice(12));
      return new TextDecoder().decode(pt);
    }
  };
})();

/* ============ 3. 状态 ============ */
const DEFAULT = {
  name: '', room: '', avatar: { t: 'k', c: '#FF6B9D' },
  theme: 'day', layer: 'std', interval: 8, encrypt: true, hd: true, mapStyle: 'macaron',
  trail: true, notify: false, sound: true, welcome: false, demo: false,
  otrack: true
};
const S = Object.assign({}, DEFAULT, load('lklx.cfg') || {});
let me = null;              // 我的真实位置(GCJ)
let peer = null;            // 对方 {lat,lng,...,at}
let peerHistory = [];       // 对方轨迹点
let myTrail = [];
let myMarker = null, peerMarker = null, peerLine = null, myLine = null;
let map = null, amap = null, tileSat = null, tileRoad = null, peerEl = null;
let myMarkSig = '', peerMarkSig = '';
let watchId = null, pubTimer = null, pubFail = 0, es = null, lastPub = 0;
const seenIds = new Set();
const chat = [];

function load(k) { try { return JSON.parse(localStorage.getItem(k) || 'null'); } catch (e) { return null; } }

/* ---- 原生桥：安卓壳里设置存在 SharedPreferences，换端口/清缓存都不丢 ---- */
function hasNative() { return typeof LKLX !== 'undefined' && LKLX && LKLX.cfg; }
function nativeGet() {
  if (!hasNative()) return null;
  try { return JSON.parse(LKLX.cfg() || 'null'); } catch (e) { return null; }
}
function nativePush() {
  if (!hasNative()) return;
  try {
    LKLX.cfg(JSON.stringify({
      room: S.room || '', nm: S.name || '',
      av: JSON.stringify(S.avatar || { t: 'k', c: '#FF6B9D' }),
      intv: S.interval || 8, enc: !!S.encrypt, bg: true, near: 500
    }));
  } catch (e) {}
}
function save() {
  const { name, room, avatar, theme, layer, interval, encrypt, trail, notify, sound, welcome, demo, hd, otrack, mapStyle } = S;
  localStorage.setItem('lklx.cfg', JSON.stringify(
    { name, room, avatar, theme, layer, interval, encrypt, trail, notify, sound, welcome, demo, hd, otrack, mapStyle }));
  nativePush();
}

/* ============ 4. 工具 ============ */
function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }

function haversine(a, b) {
  if (!a || !b) return null;
  const R = 6371000, r = Math.PI / 180;
  const dLat = (b.lat - a.lat) * r, dLng = (b.lng - a.lng) * r;
  const s = Math.sin(dLat / 2) ** 2 +
    Math.cos(a.lat * r) * Math.cos(b.lat * r) * Math.sin(dLng / 2) ** 2;
  return 2 * R * Math.asin(Math.sqrt(s));
}
function fmtDist(m) {
  if (m == null) return ['--', ''];
  if (m < 950) return [Math.round(m / 10) * 10, '米'];
  if (m < 100000) return [(m / 1000).toFixed(1), '公里'];
  return [(m / 1000).toFixed(0), '公里'];
}
function ago(t) {
  if (!t) return '从未';
  const d = Math.max(0, (Date.now() - t) / 1000);
  if (d < 8) return '刚刚';
  if (d < 60) return Math.floor(d) + ' 秒前';
  if (d < 3600) return Math.floor(d / 60) + ' 分钟前';
  if (d < 86400) return Math.floor(d / 3600) + ' 小时前';
  return Math.floor(d / 86400) + ' 天前';
}
function hhmm(t) {
  const d = new Date(t || Date.now());
  return String(d.getHours()).padStart(2, '0') + ':' + String(d.getMinutes()).padStart(2, '0');
}
function randRoom() {
  const A = 'abcdefghjkmnpqrstuvwxyz23456789';
  let s = '';
  for (let i = 0; i < 8; i++) s += A[Math.floor(Math.random() * A.length)];
  return 'kitty-' + s;
}
function myId() {
  // 安卓壳里用原生生成的稳定 id，避免每次重开身份都变（变了两端会认不出自己）
  if (typeof LKLX !== 'undefined' && LKLX && LKLX.id) {
    try { const nid = LKLX.id(); if (nid) { localStorage.setItem('lklx.id', nid); return nid; } } catch (e) {}
  }
  let id = localStorage.getItem('lklx.id');
  if (!id) { id = Math.random().toString(36).slice(2, 10); localStorage.setItem('lklx.id', id); }
  return id;
}
let toastT = null;
function toast(msg, heart) {
  const el = $('#toast');
  el.className = 'toast on' + (heart ? ' heart' : '');
  el.innerHTML = (heart ? Kitty.heart('#fff', 15) : '') + '<span>' + esc(msg) + '</span>';
  clearTimeout(toastT);
  toastT = setTimeout(() => { el.className = 'toast'; }, 2100);
}
function heartsBurst(n) {
  n = n || 7;
  const colors = ['#FF6B9D', '#FF4E8A', '#FFB3CC', '#FF93B9', '#F24E86'];
  for (let i = 0; i < n; i++) {
    const d = document.createElement('div');
    d.className = 'floaty';
    d.innerHTML = Kitty.heart(colors[i % colors.length], 20 + Math.random() * 26);
    d.style.left = (18 + Math.random() * 64) + 'vw';
    d.style.bottom = (18 + Math.random() * 28) + 'vh';
    d.style.animationDelay = (i * 90) + 'ms';
    document.body.appendChild(d);
    setTimeout(() => d.remove(), 2100);
  }
}
function vibe(ms) { if (navigator.vibrate) navigator.vibrate(ms || 14); }

/* ============ 5. 地图 ============ */
/* 地图改用高德官方 JS API：矢量渲染，文字在设备上实时绘制。
   旧方案是「图片瓦片拼贴」，屏幕上每个地名都是 256px 小图被放大 3.75 倍的产物，
   所以看着发虚。矢量渲染没有这个问题，配色/图标/路名层级也和高德 App 一致。
   ★ 注意：AMap 坐标是 [经度, 纬度]，和 Leaflet 的 [纬度, 经度] 相反。 */
const MAP_STYLES = [
  ['macaron', '马卡龙'], ['fresh', '清新'], ['normal', '标准'], ['light', '淡雅'],
  ['whitesmoke', '烟灰'], ['graffiti', '涂鸦'], ['blue', '蓝调']
];

function mapStyleId() {
  if (S.theme === 'night') return 'amap://styles/dark';
  return 'amap://styles/' + (S.mapStyle || 'macaron');
}

function initMap() {
  /* 适配层：保留原来的 map.xxx 调用方式，内部转成 AMap 的接口。
     即使高德脚本没加载出来，这一层也必须存在，否则别处的 map.setView 会直接报错白屏。 */
  map = {
    _inited: false,
    getZoom: () => (amap ? amap.getZoom() : 13),
    setView(ll, z) { if (amap) amap.setZoomAndCenter(z || 13, [ll[1], ll[0]], true); },
    flyTo(ll, z) { if (amap) amap.setZoomAndCenter(z || 13, [ll[1], ll[0]], true); },
    fitBounds(pts) {
      if (!amap || !pts || !pts.length) return;
      let a = 90, b = -90, c = 180, d = -180;
      pts.forEach(p => {
        const la = Array.isArray(p) ? p[0] : p.lat, ln = Array.isArray(p) ? p[1] : p.lng;
        if (la < a) a = la; if (la > b) b = la;
        if (ln < c) c = ln; if (ln > d) d = ln;
      });
      if (a === b && c === d) { amap.setZoomAndCenter(15, [c, a], true); return; }
      try { amap.setBounds(new AMap.Bounds([c, a], [d, b]), false, [70, 90, 200, 70]); }
      catch (e) { amap.setZoomAndCenter(13, [(c + d) / 2, (a + b) / 2], true); }
    },
    removeLayer(o) { if (o && o.setMap) { try { o.setMap(null); } catch (e) {} } },
    on(ev, fn) { if (amap) amap.on(ev, fn); }
  };
  if (typeof AMap === 'undefined') {
    const el = document.getElementById('map');
    if (el) el.innerHTML = '<div style="padding:60px 24px;text-align:center;color:#C2688A;'
      + 'font-size:13px;line-height:1.9">地图组件没能加载出来<br>'
      + '<span style="font-size:12px;opacity:.75">检查一下网络，然后下拉刷新</span></div>';
    return;
  }
  amap = new AMap.Map('map', {
    zoom: 13, center: [113.2644, 23.1291], viewMode: '2D',
    resizeEnable: true, zooms: [3, 19], mapStyle: mapStyleId()
  });
  amap.on('click', () => {
    const s = $('#sheet');
    if (s && s.classList.contains('up')) s.classList.remove('up');
  });
  /* 容器尺寸变化后必须 resize，否则地图会糊或错位 */
  setTimeout(() => { try { amap.resize(); } catch (e) {} }, 300);
  setTimeout(() => { try { amap.resize(); } catch (e) {} }, 1200);
}

function applyLayer() {
  if (!amap) return;
  [tileSat, tileRoad].forEach(t => { if (t) { try { amap.remove(t); } catch (e) {} } });
  tileSat = tileRoad = null;
  if (S.layer === 'sat') {
    tileSat = new AMap.TileLayer.Satellite({ zIndex: 2 });
    tileRoad = new AMap.TileLayer.RoadNet({ zIndex: 3 });
    amap.add(tileSat); amap.add(tileRoad);
  }
  try { amap.setMapStyle(mapStyleId()); } catch (e) {}
}

/* ============ 6. 标记 ============ */
const MK_AX = 65, MK_AY = 64;   // 与 markerHTML 的锚点对齐（底边居中）
function markSig(av, name, isMe) {
  return name + '|' + (av && av.c ? av.c : '') + '|' + (isMe ? '1' : '0');
}
function mkMarkEl(av, name, isMe) {
  const d = document.createElement('div');
  d.className = 'mki';
  d.style.cssText = 'width:130px;height:96px;position:relative';
  d.innerHTML = Kitty.markerHTML(name, av, { me: isMe, ring: isMe ? '#5FCBB2' : '#FF6B9D', size: 52 });
  return d;
}
function upsertMe(lat, lng) {
  if (!amap) return;
  const sig = markSig(S.avatar, S.name || '我', true);
  if (!myMarker) {
    myMarker = new AMap.Marker({
      position: [lng, lat], content: mkMarkEl(S.avatar, S.name || '我', true),
      offset: new AMap.Pixel(-MK_AX, -MK_AY), zIndex: 500, clickable: false, map: amap
    });
    myMarkSig = sig;
  } else {
    myMarker.setPosition([lng, lat]);
    if (sig !== myMarkSig) {
      myMarker.setContent(mkMarkEl(S.avatar, S.name || '我', true));
      myMarkSig = sig;
    }
  }
}
function upsertPeer(p, animate) {
  if (!amap) return;
  const sig = markSig(p.av, p.n || '宝贝', false);
  if (!peerMarker) {
    peerEl = mkMarkEl(p.av, p.n || '宝贝', false);
    peerMarker = new AMap.Marker({
      position: [p.lng, p.lat], content: peerEl,
      offset: new AMap.Pixel(-MK_AX, -MK_AY), zIndex: 1000, map: amap
    });
    peerMarkSig = sig;
    if (map.getZoom() < 11) map.setView([p.lat, p.lng], 13);
  } else {
    peerMarker.setPosition([p.lng, p.lat]);
    if (sig !== peerMarkSig) {
      peerEl = mkMarkEl(p.av, p.n || '宝贝', false);
      peerMarker.setContent(peerEl);
      peerMarkSig = sig;
    }
  }
  if (animate && peerEl) {
    const m = peerEl.querySelector('.mk');
    if (m) { m.classList.add('pulse'); setTimeout(() => m.classList.remove('pulse'), 720); }
  }
}

/* ============ 7. 发布 / 订阅 ============ */
async function publish(obj) {
  if (!S.room) return;
  const plain = JSON.stringify(obj);
  let body = plain;
  if (S.encrypt) {
    if (!Crypto_.on) {
      // 非安全上下文（http / 本地文件）拿不到 WebCrypto。
      // 绝不能假装加密：明确告警后才降级，并且只在界面上显著提示。
      insecureWarn();
      body = plain;
    } else {
      try { body = await Crypto_.enc(plain, S.room); }
      catch (e) { failConn(); return; }   // 加密失败就干脆不发，绝不明文外泄
    }
  }
  try {
    const r = await fetch(NTFY + '/' + topicOf(S.room), {
      method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: body
    });
    if (r.ok) { pubFail = 0; setConn('on'); } else { failConn(); }
  } catch (e) { failConn(); }
}
function failConn() { pubFail++; if (pubFail >= 2) setConn('off'); }

/* 非安全上下文时，位置无法在本机加密 —— 明确、反复地告诉用户 */
let insecureTold = false;
function insecureWarn() {
  S.insecure = true;
  if (insecureTold) return;
  insecureTold = true;
  setConn('warn');
  toast('⚠️ 当前环境不支持加密，位置是明文发出的', true);
  const n = $('#secNote');
  if (n) { n.innerHTML = warnCard(); }
}
function warnCard() {
  return `<div class="card warn">
    <h4>⚠️ 当前没有加密</h4>
    <div class="note">
      这个地址不是 HTTPS，浏览器不给用加密接口，所以位置会<b>以明文</b>经过中转服务器。<br>
      正式使用时请从 <b>https://</b> 开头的地址打开，或使用安卓版 App —— 那时会自动加密。
    </div>
  </div>`;
}
function setConn(state) {
  const d = $('#dot'), t = $('#connText');
  if (S.demo) { d.className = 'dot demo'; t.textContent = '演示模式'; return; }
  if (state === 'warn') { d.className = 'dot warn'; t.textContent = '未加密共享中'; }
  else if (state === 'on') {
    if (S.encrypt && !Crypto_.on) { d.className = 'dot warn'; t.textContent = '未加密共享中'; }
    else { d.className = 'dot on'; t.textContent = '实时共享中'; }
  }
  else if (state === 'off') { d.className = 'dot off'; t.textContent = '连接断开'; }
  else { d.className = 'dot'; t.textContent = S.room ? '连接中…' : '未设置'; }
}
async function onRaw(message) {
  let txt = message;
  if (txt.indexOf('E1:') === 0) {
    try { txt = await Crypto_.dec(txt, S.room); }
    catch (e) { return; }   // 别人的消息 / 暗号不对
  }
  let o; try { o = JSON.parse(txt); } catch (e) { return; }
  if (!o) return;
  // iPhone 锁屏时的后台补点：OwnTracks 发来的原始报文
  if (o._type !== undefined || (!o.k && typeof o.lat === 'number' && typeof o.lon === 'number')) {
    if (S.otrack === false) return;
    o = fromOwnTracks(o);
    if (!o) return;
  }
  if (o.id === myId()) return;
  if (o.k === 'pos') onPeerPos(o);
  else if (o.k === 'msg') onPeerMsg(o);
  else if (o.k === 'sos') onPeerSos(o);
}
/* OwnTracks 报的是原始 GPS（WGS84）且不经加密，
   必须转成 GCJ-02 才能跟高德地图的底图对上。 */
function fromOwnTracks(o) {
  if (o._type && o._type !== 'location') return null;   // transition / lwt 等忽略
  const la = +o.lat, lo = +o.lon;
  if (!isFinite(la) || !isFinite(lo) || !GCJ.ok(la, lo)) return null;
  const g = GCJ.wgs2gcj(la, lo);
  const ts = +(o.tst || o.t || 0);
  return {
    k: 'pos', id: 'ot:' + (o.tid || 'peer'), n: o.name || '', av: null,
    lat: +g[0].toFixed(6), lon: +g[1].toFixed(6),
    ac: o.acc ? Math.round(o.acc) : 0,
    sp: o.vel ? +(+o.vel).toFixed(1) : 0,
    b: (typeof o.batt === 'number' && o.batt >= 0) ? Math.round(o.batt) : null,
    cg: null,
    t: ts ? ts * 1000 : Date.now(),
    ot: 1
  };
}
function onPeerPos(o) {
  if (!GCJ.ok(o.lat, o.lon)) return;
  const fresh = !peer || o.t > peer.t;
  peer = {
    lat: o.lat, lng: o.lon,
    av: o.av || (peer && peer.av) || null,
    n: o.n || (peer && peer.n) || '',
    acc: o.ac, speed: o.sp, batt: o.b, chg: o.cg,
    ot: !!o.ot, at: Date.now(), t: o.t
  };
  if (fresh) {
    if (S.trail) {
      peerHistory.push({ lat: o.lat, lng: o.lon, t: o.t });
      if (peerHistory.length > 400) peerHistory.shift();
      localStorage.setItem('lklx.trail', JSON.stringify(peerHistory));
      drawTrail();
    }
    upsertPeer(peer, true);
    renderPeer();
  }
}
function onPeerMsg(o) {
  chat.push({ me: false, text: o.msg, t: o.t || Date.now() });
  if (chat.length > 200) chat.shift();
  renderChat();
  heartsBurst(o.hearts ? 10 : 4);
  vibe([30, 60, 30]);
  toast((peer && peer.n ? peer.n : '对方') + '：' + o.msg, true);
  if (S.notify && Notification && Notification.permission === 'granted') {
    try { new Notification('💕 ' + (peer && peer.n ? peer.n : '宝贝'), { body: o.msg, tag: 'lklx' }); } catch (e) {}
  }
  if (S.sound) blip();
}
function onPeerSos(o) {
  toast('⚠ ' + (o.n || '对方') + ' 发出求助！', false);
  if (S.notify && Notification && Notification.permission === 'granted') {
    try { new Notification('🆘 SOS 求助', { body: (o.n || '对方') + ' 需要你', tag: 'sos' }); } catch (e) {}
  }
  heartsBurst(12); vibe([80, 60, 80, 60, 220]);
}
function blip() {
  try {
    const C = window.AudioContext || window.webkitAudioContext; if (!C) return;
    const ctx = new C(), o = ctx.createOscillator(), g = ctx.createGain();
    o.type = 'sine'; o.frequency.value = 880;
    g.gain.setValueAtTime(0.0001, ctx.currentTime);
    g.gain.exponentialRampToValueAtTime(0.12, ctx.currentTime + 0.01);
    g.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + 0.25);
    o.connect(g); g.connect(ctx.destination); o.start(); o.stop(ctx.currentTime + 0.26);
    setTimeout(() => ctx.close(), 600);
  } catch (e) {}
}

function connect() {
  if (es) { try { es.close(); } catch (e) {} es = null; }
  if (!S.room || S.demo) { setConn(S.demo ? 'demo' : ''); return; }
  setConn('');
  try {
    es = new EventSource(NTFY + '/' + topicOf(S.room) + '/sse');
    es.onopen = () => { setConn('on'); };
    es.onmessage = ev => {
      setConn('on');
      let d; try { d = JSON.parse(ev.data); } catch (e) { return; }
      if (d.event === 'message' && d.id) {
        if (seenIds.has(d.id)) return;
        seenIds.add(d.id);
        if (seenIds.size > 300) seenIds.clear();
        onRaw(d.message);
      }
    };
    es.onerror = () => setConn('off');
  } catch (e) { setConn('off'); }
}
async function catchUp() {
  if (!S.room || S.demo) return;
  try {
    const r = await fetch(NTFY + '/' + topicOf(S.room) + '/json?poll=1&since=6h');
    const lines = (await r.text()).trim().split('\n').filter(Boolean);
    for (const ln of lines) {
      let d; try { d = JSON.parse(ln); } catch (e) { continue; }
      if (d.event !== 'message') continue;
      if (d.id) { if (seenIds.has(d.id)) continue; seenIds.add(d.id); }
      await onRaw(d.message);
    }
    if (peer) { renderPeer(); }
  } catch (e) {}
}

/* ============ 8. 定位 ============ */
/* iOS/Safari 的定位授权必须在「用户点击」时发起，否则权限框根本不弹。
   另外微信、QQ 等内置浏览器会直接拦截定位。这里两种情况都单独处理。 */
const IN_APP_BROWSER = (function () {
  const u = navigator.userAgent || '';
  if (/MicroMessenger/i.test(u)) return '微信';
  if (/QQBrowser|QQ\//i.test(u)) return 'QQ';
  if (/Weibo/i.test(u)) return '微博';
  if (/Douyin|aweme/i.test(u)) return '抖音';
  if (/Alipay/i.test(u)) return '支付宝';
  return null;
})();
const IS_IOS = /iPhone|iPad|iPod/i.test(navigator.userAgent || '') ||
  (navigator.platform === 'MacIntel' && (navigator.maxTouchPoints || 0) > 1);
const IS_STANDALONE = ('standalone' in navigator) ? navigator.standalone
  : (window.matchMedia && window.matchMedia('(display-mode: standalone)').matches);

let geoState = 'unknown';   // unknown | ok | denied | fail

function geoBar(html, btnText, onClick, kind, btn2) {
  const el = $('#geoBar'); if (!el) return;
  el.className = 'geobar' + (kind ? ' ' + kind : '');
  el.innerHTML = '<div class="grow">' + html + '</div>';
  if (btnText) {
    const b = document.createElement('button');
    b.type = 'button'; b.textContent = btnText;
    b.addEventListener('click', ev => { ev.preventDefault(); onClick(); });
    el.appendChild(b);
  }
  if (btn2) {
    const b2 = document.createElement('button');
    b2.type = 'button'; b2.className = 'ghost'; b2.textContent = btn2[0];
    b2.addEventListener('click', ev => { ev.preventDefault(); btn2[1](); });
    el.appendChild(b2);
  }
  el.hidden = false;
}

/* 复制当前网址 —— 用来「换个浏览器打开」或发给对方 */
function copyUrl(tip) {
  const u = location.href;
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(u)
      .then(() => toast(tip || '网址已复制', true))
      .catch(() => prompt('复制这个网址：', u));
  } else prompt('复制这个网址：', u);
}
function geoBarHide() { const el = $('#geoBar'); if (el) el.hidden = true; }

/* 用户点击后调用：这一步带着手势，iOS 才会弹权限框 */
function askGeo() {
  if (hasNative()) {                 // 安卓壳：定位交给后台服务，不用浏览器权限
    let o = null;
    try { o = JSON.parse(LKLX.geo() || 'null'); } catch (e) {}
    if (o && o.err) {
      geoBar('<b>手机还没定位到</b>' + esc(o.err) +
        '<br>确认系统「位置信息」是开着的，并且允许「两颗心」使用位置，然后重试',
        '重试', askGeo, 'warn');
      return;
    }
    geoBarHide();
    startNativeGeo();
    return;
  }
  if (!navigator.geolocation) {
    geoBar('<b>这台设备不支持定位</b>', null, null, 'warn');
    return;
  }
  geoState = 'unknown';
  geoBar('<b>正在请求定位…</b>请在弹窗里点「允许」', null, null);
  navigator.geolocation.getCurrentPosition(
    () => { geoBarHide(); startGeo(); },
    err => onGeoErr(err),
    { enableHighAccuracy: true, timeout: 15000, maximumAge: 0 }
  );
}

/* 浏览器拒绝定位时，给出的提示必须是这台设备上真正能照做的步骤。
   安卓和 iOS 的设置路径完全不同，之前一律按 iOS 写，安卓用户照着找不到。 */
function deniedTip(stage) {
  if (IS_IOS) {
    return '<br>' + (IS_STANDALONE
      ? '设置 → 隐私与安全性 → 定位服务 → 找到「两颗心」→ 改成「使用App期间」'
      : '设置 → 隐私与安全性 → 定位服务 → 找到「Safari 网站」→ 改成「允许」');
  }
  return '<br>系统里允许过也可能被浏览器单独拦下：点地址栏左边的 <b>🔒 / ⓘ / 盾牌</b> 图标 → 网站设置（权限）→ 把「位置」改成<b>允许</b>，再刷新页面。'
    + '<br>找不到这个开关、或者改了也没用，就是<b>这个浏览器不把定位给网页</b>（Via、夸克、UC 这类轻量浏览器和微信里都会这样）。'
    + '<br>换一个浏览器打开同一个网址，或者直接用<b>安卓版「两颗心」App</b>。';
}
function onGeoErr(err) {
  const c = (err && err.code) || 0;
  const ec = '<small class="ec">错误码 ' + c + ' · ' + esc(geoStage()) + '</small>';
  if (c === 1) {
    geoState = 'denied';
    geoBar('<b>定位被拒绝了</b>' + deniedTip() + ec,
      '再试一次', askGeo, 'warn', ['复制网址', () => copyUrl('网址已复制，粘到别的浏览器里打开')]);
  } else {
    geoState = 'fail';
    geoBar('<b>暂时拿不到位置</b>' +
      (c === 3 ? '定位请求超时了，多半是室内信号弱 —— 到窗边或门外再试一次。'
               : '确认手机「定位服务」是开着的，或到窗边再试。') + ec,
      '重试', askGeo, 'warn');
  }
}
/* 用来判断错误是「刚授权就失败」还是「跑起来之后才失败」 */
function geoStage() {
  return geoState === 'ok' ? '运行中丢失' : '未授权';
}

/* —— 安卓版 App 里的原生定位 ——
   壳子里本来就跑着一个后台定位服务（和「后台补点」用的是同一个），比浏览器的
   geolocation 稳得多：WebView、内置浏览器经常把网页定位请求无声拒掉，用户
   明明授权了也拿不到位置。原生给的坐标已经是 GCJ-02，直接用，不要再纠偏。 */
function nativeFix() {
  if (typeof LKLX === 'undefined' || !LKLX || !LKLX.geo) return null;
  try {
    const o = JSON.parse(LKLX.geo() || 'null');
    if (!o || !o.ok || !o.lat) return null;
    return { lat: o.lat, lng: o.lon, acc: o.ac || 0, speed: o.sp || 0, at: o.t || Date.now() };
  } catch (e) { return null; }
}
function nativeSharing() {
  try { return typeof LKLX !== 'undefined' && !!LKLX && !!LKLX.sharing && LKLX.sharing() === '1'; }
  catch (e) { return false; }
}

/* 拿到一个位置之后要做的所有事 —— 浏览器定位和原生定位两条路共用 */
function applyFix(lat, lng, acc, speed, raw) {
  geoState = 'ok'; geoBarHide();
  me = { lat: lat, lng: lng, raw: raw || null, acc: acc, speed: speed, head: null, at: Date.now() };
  upsertMe(me.lat, me.lng);
  if (!peer && map && !map._inited) { map.setView([me.lat, me.lng], 15); map._inited = true; }
  if (S.trail) {
    myTrail.push({ lat: me.lat, lng: me.lng, t: Date.now() });
    if (myTrail.length > 400) myTrail.shift();
    drawTrail();
  }
  renderPeer();
  const chip = $('#gpsChip');
  if (chip) chip.textContent = '±' + Math.round(acc || 0) + 'm';
}

let natTimer = null, natMiss = 0, natFellBack = false;
function startNativeGeo() {
  if (natTimer) clearInterval(natTimer);
  const tick = () => {
    const f = nativeFix();
    if (f) {
      natMiss = 0;
      applyFix(f.lat, f.lng, f.acc, f.speed, null);
    } else if (++natMiss === 6 && !natFellBack) {
      // 壳子里等了 20 秒还没等到原生定位（后台服务可能没起来或被系统停了），
      // 退回浏览器定位兜底 —— 两条路都不行时才提示用户。
      natFellBack = true;
      browserGeo();
    }
    quotaRefreshHint();
  };
  tick();
  natTimer = setInterval(tick, 4000);
}

function startGeo() {
  // 安卓壳（两颗心 App）里有后台定位服务，优先用它 —— WebView 里浏览器自己的
  // 定位经常被无声拒绝，用户明明授权了也拿不到点。
  if (hasNative()) { startNativeGeo(); return; }
  browserGeo();
}

function browserGeo() {
  if (!navigator.geolocation) { onGeoErr({ code: 2 }); return; }
  if (watchId != null) { try { navigator.geolocation.clearWatch(watchId); } catch (e) {} }
  watchId = navigator.geolocation.watchPosition(pos => {
    const c = pos.coords;
    const g = GCJ.wgs2gcj(c.latitude, c.longitude);
    applyFix(g[0], g[1], c.accuracy, c.speed, [c.latitude, c.longitude]);
  }, err => {
    // 拿不到定位时绝不伪造坐标 —— 否则对方会看到你在广州。
    if (geoState !== 'ok') onGeoErr(err);
    if (!me && map && !map._inited) { map.setView([34.5, 108.9], 4); map._inited = true; }
  }, { enableHighAccuracy: true, maximumAge: 3000, timeout: 20000 });
}
async function battery() {
  try {
    if (!navigator.getBattery) return null;
    const b = await navigator.getBattery();
    return { level: Math.round(b.level * 100), charging: b.charging };
  } catch (e) { return null; }
}
/* ntfy.sh 免费额度每天只有 250 条消息。旧实现每 8 秒无条件发一条 = 一天 10800 条，
   大约半小时就烧光额度，之后位置彻底不再更新，而且不会报任何错。
   这里改成：只在真的移动时才发 + 静止时低频保活，并按剩余额度自动放慢。 */
const QUOTA_DAY = 240;          // 留 10 条余量给握手和手动刷新
const MOVE_M = 35;              // 位移超过 35 米才算「动了」
const CHECK_MS = 10000;         // 每 10 秒检查一次（检查 ≠ 发送）
let qLastPt = null, qLastAt = 0;

function quotaToday() {
  const d = new Date().toISOString().slice(0, 10);
  let q = { d: d, n: 0 };
  try {
    const s = JSON.parse(localStorage.getItem('lklx.quota') || 'null');
    if (s && s.d === d) q = s;
  } catch (e) {}
  return q;
}
function quotaLeft() {
  // 安卓壳里真正在发位置的是后台服务，额度要问它，本地计数器看不到那部分
  if (nativeSharing()) {
    try {
      const o = JSON.parse(LKLX.geo() || 'null');
      if (o && typeof o.q === 'number') return o.q;
    } catch (e) {}
  }
  return Math.max(0, QUOTA_DAY - quotaToday().n);
}
function quotaRefreshHint() {
  const el = document.getElementById('quotaHint');
  if (el) el.textContent = '今日剩余 ' + quotaLeft() + ' 条';
}
function quotaSpend() {
  const q = quotaToday(); q.n++;
  try { localStorage.setItem('lklx.quota', JSON.stringify(q)); } catch (e) {}
  const el = document.getElementById('quotaHint');
  if (el) el.textContent = '今日剩余 ' + quotaLeft() + ' 条';
}
function hoursLeftToday() {
  const n = new Date();
  return Math.max(0.5, 24 - (n.getHours() + n.getMinutes() / 60));
}
/* 额度越少，两次发送的间隔越长 —— 自动把额度摊到剩下的一天里 */
function pubGapMs() {
  const left = quotaLeft();
  if (left <= 0) return Infinity;
  const perHour = left / hoursLeftToday();
  if (perHour >= 30) return Math.max(5000, (S.interval || 8) * 1000);
  if (perHour >= 12) return 20000;
  if (perHour >= 5) return 45000;
  if (perHour >= 2) return 90000;
  return 150000;
}
function beatGapMs() {
  const left = quotaLeft();
  if (left <= 0) return Infinity;
  const perHour = left / hoursLeftToday();
  if (perHour >= 8) return 10 * 60 * 1000;
  if (perHour >= 3) return 20 * 60 * 1000;
  if (perHour >= 1) return 35 * 60 * 1000;
  return 50 * 60 * 1000;
}

async function pubPos(force) {
  if (!me || !S.room || S.demo) return;
  if (me.fake) return;   // 绝不把伪造坐标发出去
  // 安卓壳里后台服务自己会上报位置（关屏也照发），网页端再发一遍等于
  // 把每天 250 条的免费额度翻倍烧掉。既然原生在发，这里就只管显示。
  if (nativeSharing()) { setConn('on'); pubFail = 0; return; }
  if (!force && quotaLeft() <= 0) return;   // 额度用完就只收不发

  const now = Date.now();
  const since = now - qLastAt;
  if (!force) {
    const moved = qLastPt ? haversine(qLastPt, me) : Infinity;
    if (moved >= MOVE_M) {
      if (since < pubGapMs()) return;       // 移动也受额度节流
    } else if (since < beatGapMs()) {
      return;                               // 没动、又没到心跳时间 → 不发
    }
  }
  qLastPt = { lat: me.lat, lng: me.lng };
  qLastAt = now;
  quotaSpend();
  const b = await battery();
  publish({
    v: 1, k: 'pos', id: myId(), n: S.name || '我', av: S.avatar,
    lat: +me.lat.toFixed(6), lon: +me.lng.toFixed(6),
    ac: Math.round(me.acc || 0), sp: me.speed ? +me.speed.toFixed(1) : 0,
    b: b ? b.level : null, cg: b ? b.charging : null, t: Date.now()
  });
}
function restartPub() {
  clearInterval(pubTimer);
  qLastPt = null;
  if (S.demo || !S.room) return;
  pubPos(true);                                  // 启动时先报一次位置
  pubTimer = setInterval(() => pubPos(false), CHECK_MS);
}

/* ============ 9. 轨迹 ============ */
function drawTrail() {
  if (!amap) return;
  if (peerLine) { try { peerLine.setMap(null); } catch (e) {} peerLine = null; }
  if (myLine) { try { myLine.setMap(null); } catch (e) {} myLine = null; }
  if (!S.trail) return;
  if (peerHistory.length > 1) {
    peerLine = new AMap.Polyline({
      path: peerHistory.map(p => [p.lng, p.lat]),
      strokeColor: '#FF6B9D', strokeWeight: 4, strokeOpacity: 0.75,
      strokeStyle: 'dashed', strokeDasharray: [1, 9], lineJoin: 'round', lineCap: 'round',
      zIndex: 200, map: amap
    });
  }
  if (myTrail.length > 1) {
    myLine = new AMap.Polyline({
      path: myTrail.map(p => [p.lng, p.lat]),
      strokeColor: '#5FCBB2', strokeWeight: 4, strokeOpacity: 0.6,
      strokeStyle: 'dashed', strokeDasharray: [1, 9], lineJoin: 'round', lineCap: 'round',
      zIndex: 150, map: amap
    });
  }
}

/* ============ 10. 演示模式 ============ */
let demoTimer = null, demoAngle = 0;
const DEMO_CENTER = [23.1291, 113.2644];   // 广州塔附近
function startDemo() {
  S.demo = true; save();
  setConn('demo');
  if (!me) {
    const g = GCJ.wgs2gcj(DEMO_CENTER[0], DEMO_CENTER[1]);
    me = { lat: g[0] + 0.004, lng: g[1] - 0.005, acc: 12, at: Date.now() };
    upsertMe(me.lat, me.lng);
  }
  map.setView([DEMO_CENTER[0], DEMO_CENTER[1]], 14);
  const names = ['小猫咪', '宝贝', '小笨蛋', 'Kitty'];
  const cols = ['#FF6B9D', '#F24E86', '#FF93B9', '#7FD8C4'];
  peer = {
    lat: DEMO_CENTER[0] + 0.012, lng: DEMO_CENTER[1] + 0.014,
    n: S.demoName || '小美', av: { t: 'k', c: '#F24E86' },
    acc: 18, speed: 1.2, batt: 76, chg: false, at: Date.now(), t: Date.now()
  };
  upsertPeer(peer, true);
  if (me) map.fitBounds([[me.lat, me.lng], [peer.lat, peer.lng]], { padding: [70, 150] });
  clearInterval(demoTimer);
  demoTimer = setInterval(() => {
    demoAngle += 0.09;
    const r = 0.013;
    const lat = DEMO_CENTER[0] + 0.010 + Math.sin(demoAngle) * r * 0.75;
    const lng = DEMO_CENTER[1] + 0.013 + Math.cos(demoAngle * 0.8) * r;
    peer.lat = lat; peer.lng = lng; peer.at = Date.now(); peer.t = Date.now();
    peer.speed = +(0.4 + Math.abs(Math.sin(demoAngle * 1.7)) * 2.2).toFixed(1);
    peer.batt = Math.max(20, Math.round(76 - (demoAngle * 2) % 40));
    peer.acc = 8 + Math.round(Math.abs(Math.cos(demoAngle)) * 22);
    upsertPeer(peer, false);
    if (S.trail && Math.random() < 0.5) {
      peerHistory.push({ lat, lng, t: Date.now() });
      if (peerHistory.length > 400) peerHistory.shift();
      drawTrail();
    }
    renderPeer();
  }, 2500);
  renderPeer(); renderTrailPanel();
  toast('演示模式：这是模拟的对方位置');
}
function stopDemo() {
  S.demo = false; save();
  clearInterval(demoTimer); demoTimer = null;
  peer = null; peerHistory = [];
  if (peerMarker) { map.removeLayer(peerMarker); peerMarker = null; }
  if (peerLine) { map.removeLayer(peerLine); peerLine = null; }
  renderPeer(); renderTrailPanel();
  connect(); restartPub();
  toast('已切换到真实模式');
}

/* ============ 11. 渲染 ============ */
function renderPeer() {
  const $av = $('#peerAv'), $nm = $('#peerName'), $sb = $('#peerSub'), $d = $('#peerDist');
  const $dl = $('#peerDistLbl');
  if (!peer) {
    $av.innerHTML = `<div class="ring">${Kitty.face({ bow: '#FFC9DD', w: 46, h: 40 })}</div>
      <span class="live idle"></span>`;
    $nm.textContent = S.demo ? '小美' : '等待对方…';
    $sb.innerHTML = S.room ? '把暗号发给女朋友，让她打开同一个网址' : '还没设置房间暗号';
    $d.textContent = '--'; $dl.textContent = '距离';
    $('#panelPeer').innerHTML = `<div class="empty">${Kitty.heart('#FFD3E2', 40)}
      <div>还没有收到对方的位置</div>
      <div style="font-size:11.5px;margin-top:6px">让她打开同一个网址，输入同一个暗号即可</div></div>`;
    return;
  }
  const av = Kitty.avatarHTML(peer.av, 54);
  const online = Date.now() - peer.at < 45000;
  $av.innerHTML = `<div class="ring">${av}</div>
    <span class="bow">${Kitty.heart('#FF4E8A', 17)}</span>
    <span class="live ${online ? '' : 'idle'}"></span>`;
  $nm.textContent = peer.n || '宝贝';
  const m = haversine(me, peer);
  const dstr = fmtDist(m);
  $d.innerHTML = dstr[0] + (dstr[1] ? '<small>' + dstr[1] + '</small>' : '');
  $dl.textContent = '距离你';
  $sb.innerHTML = '<b>' + ago(peer.at) + '</b>更新 · ' + (online ? '在线' : '可能没在看手机')
    + (peer.ot ? ' · <span style="color:#E8590C;font-weight:700">后台补点</span>' : '');
  renderPeerPanel(m);
}
function renderPeerPanel(m) {
  const $p = $('#panelPeer');
  const b = peer.batt;
  const batTxt = b == null ? '未知' : b + '%' + (peer.chg ? ' · 充电中' : '');
  const dstr = fmtDist(m);
  const nav = (name, fn) => `<div class="row"><div class="ic">${Kitty.glyph(name, 16)}</div><div class="k">${name}</div></div>`;
  $p.innerHTML = `
  <div class="card">
    <h4>${Kitty.heart('#FF6B9D', 13)} 对方状态</h4>
    <div class="row"><div class="ic">${Kitty.glyph('battery', 16)}</div>
      <div class="k">手机电量</div><div class="v">${esc(batTxt)}</div></div>
    <div class="row"><div class="ic">${Kitty.glyph('clock', 16)}</div>
      <div class="k">最后更新<em>${peer.t ? hhmm(peer.t) : ''}</em></div>
      <div class="v">${ago(peer.at)}</div></div>
    <div class="row"><div class="ic">${Kitty.glyph('speed', 16)}</div>
      <div class="k">移动速度</div>
      <div class="v">${peer.speed == null ? '—' : (peer.speed * 3.6).toFixed(1) + ' km/h'}</div></div>
    <div class="row"><div class="ic">${Kitty.glyph('gps', 16)}</div>
      <div class="k">定位精度</div><div class="v">${peer.acc ? '±' + peer.acc + ' m' : '—'}</div></div>
  </div>
  <div class="card">
    <h4>${Kitty.heart('#FF6B9D', 13)} 快捷操作</h4>
    <div class="btngrid" style="margin-bottom:9px">
      <button class="btn sm" id="btnNav">${Kitty.glyph('nav', 15, '#fff')} 导航去她那</button>
      <button class="btn sm ghost" id="btnCenter">${Kitty.glyph('eye', 15)} 地图上看她</button>
    </div>
    <div class="btngrid">
      <button class="btn sm ghost" id="btnNear">${Kitty.glyph('bell', 15)} ${dstr[0]}${dstr[1]}到了</button>
      <button class="btn sm danger" id="btnSos">${Kitty.glyph('sos', 15, '#fff')} 一键 SOS</button>
    </div>
    <div class="note" style="margin-top:11px">
      已开启<b>端到端加密</b>：位置和消息在你的手机上加密后才发出，
      即使经过公共服务器别人也读不懂内容。
    </div>
  </div>`;

  $('#btnNav').onclick = () => {
    const g = GCJ.gcj2wgs(peer.lat, peer.lng);
    if (/iPhone|iPad|iPod|Macintosh/.test(navigator.userAgent)) {
      location.href = `https://maps.apple.com/?daddr=${g[0].toFixed(6)},${g[1].toFixed(6)}&dirflg=w`;
      return;
    }
    // 交给原生：先唤起高德 App，没装就退到浏览器开网页版。
    // 绝不能在 WebView 里直接跳导航链接 —— 之前就是被当网页加载，弹"网页无法打开"还顶掉了整个页面
    if (window.LKLX && LKLX.nav) { LKLX.nav(peer.lat, peer.lng, peer.n || '她'); return; }
    location.href = `https://uri.amap.com/navigation?to=${peer.lng.toFixed(6)},${peer.lat.toFixed(6)},${encodeURIComponent(peer.n || '她')}&mode=walk&coordinate=gaode&callnative=1`;
  };
  $('#btnCenter').onclick = () => focusPeer(true);
  $('#btnNear').onclick = () => {
    const km = Math.max(0.1, Math.round(haversine(me, peer) / 100) / 10);
    toast('已设置：到达对方 ' + km + ' 公里内提醒（保持本页开启）', true);
    nearWatch = { target: km * 1000, fired: false };
  };
  $('#btnSos').onclick = () => {
    if (!confirm('确定向对方发送 SOS 求助吗？')) return;
    publish({ v: 1, k: 'sos', id: myId(), n: S.name || '我', t: Date.now() });
    heartsBurst(10);
    if (me) publish({ v: 1, k: 'pos', id: myId(), n: S.name || '我', av: S.avatar, lat: +me.lat.toFixed(6), lon: +me.lng.toFixed(6), t: Date.now() });
    toast('求助已发出', false);
  };
}
let nearWatch = null;

function renderTrailPanel() {
  const pts = S.demo ? peerHistory : peerHistory;
  const $t = $('#panelTrail');
  if (!pts.length) {
    $t.innerHTML = `<div class="empty">${Kitty.heart('#FFD3E2', 40)}
      <div>还没有轨迹记录</div>
      <div style="font-size:11.5px;margin-top:6px">开启轨迹后，会记录你们走过的地方</div></div>`;
    return;
  }
  const recent = pts.slice(-14).reverse();
  $t.innerHTML = `
  <div class="card">
    <h4>${Kitty.heart('#FF6B9D', 13)} 轨迹记录</h4>
    <div class="sw"><div class="k">记录轨迹<em>共 ${pts.length} 个点</em></div>
      <input type="checkbox" id="swTrail2" ${S.trail ? 'checked' : ''}></div>
    <div class="btngrid" style="margin-top:8px">
      <button class="btn sm ghost" id="btnFit">看完整路线</button>
      <button class="btn sm line" id="btnClearTrail">清除轨迹</button>
    </div>
  </div>
  <div class="card">
    <h4>最近经过</h4>
    ${recent.map(p => `<div class="trailrow">
        <span class="t">${hhmm(p.t)}</span>
        <span class="p">${p.lat.toFixed(4)}, ${p.lng.toFixed(4)}</span></div>`).join('')}
  </div>`;
  $('#swTrail2').onchange = e => { S.trail = e.target.checked; save(); drawTrail(); renderTrailPanel(); };
  $('#btnFit').onclick = () => {
    if (pts.length > 1) map.fitBounds(pts.map(p => [p.lat, p.lng]), { padding: [60, 90] });
  };
  $('#btnClearTrail').onclick = () => {
    if (!confirm('清除对方的历史轨迹？')) return;
    peerHistory = []; localStorage.removeItem('lklx.trail'); drawTrail(); renderTrailPanel(); toast('轨迹已清除');
  };
}

function renderChat() {
  const box = $('#chatbox');
  if (!box) return;
  if (!chat.length) {
    box.innerHTML = '<div class="msg sys">点下面的小按钮，给她发个信号 💕</div>';
    return;
  }
  box.innerHTML = chat.slice(-60).map(m => `<div class="msg ${m.me ? 'me' : 'them'}">
      ${esc(m.text)}<span class="tm">${hhmm(m.t)}</span></div>`).join('');
  box.scrollTop = box.scrollHeight;
}

function renderMe() {
  $('#panelMe').innerHTML = `
  <div id="secNote">${(S.encrypt && !Crypto_.on) ? warnCard() : ''}</div>
  <div class="card">
    <h4>${Kitty.heart('#FF6B9D', 13)} 我的形象</h4>
    <div class="field">
      <label>我的昵称</label>
      <input id="inName" maxlength="12" placeholder="给自己起个名字" value="${esc(S.name)}">
    </div>
    <label style="display:block;font-size:11.5px;font-weight:700;color:var(--ink3);letter-spacing:.8px;margin:4px 0 8px">我的头像</label>
    <div style="display:flex;align-items:center;gap:14px;margin-bottom:6px">
      <div style="width:66px;height:66px;border-radius:50%;overflow:hidden;display:grid;place-items:center;flex:none;
        background:linear-gradient(150deg,#fff,#FFEFF5);border:2.5px solid var(--p400)">
        ${Kitty.avatarHTML(S.avatar, 60)}
      </div>
      <div style="flex:1">
        <div class="swatches" id="swatches">
          ${['#FF6B9D', '#F24E86', '#FF93B9', '#7FD8C4', '#FFC93D', '#9C7BFF'].map(c =>
            `<button class="swatch ${(!S.avatar.t || S.avatar.t === 'k') && S.avatar.c === c ? 'on' : ''}" data-c="${c}">
               <span style="background:linear-gradient(140deg,${Kitty.lighten(c, 22)},${c})"></span></button>`).join('')}
        </div>
        <button class="btn sm ghost" id="btnPhoto" style="margin-top:10px">
          ${Kitty.glyph('eye', 15)} 用自己的照片</button>
        <input type="file" id="fileAv" accept="image/*" style="display:none">
      </div>
    </div>
  </div>

  <div class="card">
    <h4>${Kitty.heart('#FF6B9D', 13)} 我们的暗号</h4>
    <div class="field" style="margin-bottom:8px">
      <input id="inRoom" placeholder="例如 kitty-a1b2c3d4" value="${esc(S.room)}">
      <div class="hint">两个人必须填<b>完全一样</b>的暗号才能看到对方。别用太简单的，别人猜到了就能看到位置。</div>
    </div>
    <div class="btngrid">
      <button class="btn sm ghost" id="btnRand">${Kitty.heart('#FF6B9D', 14)} 随机生成</button>
      <button class="btn sm ghost" id="btnSaveRoom">保存暗号</button>
    </div>
    <button class="btn sm" id="btnCopy" style="width:100%;margin-top:8px">
      ${Kitty.glyph('copy', 15, '#fff')} 复制暗号发给对方</button>
    <div class="sw" style="margin-top:6px">
      <div class="k">端到端加密<em>暗号当密钥，服务器读不懂内容</em></div>
      <input type="checkbox" id="swEnc" ${S.encrypt ? 'checked' : ''}>
    </div>
  </div>

  <div class="card">
    <h4>${Kitty.heart('#FF6B9D', 13)} 定位与后台</h4>
    <div class="field" style="margin-bottom:4px">
      <label>位置更新频率：${S.interval} 秒</label>
      <input type="range" id="inInt" min="5" max="60" step="1" value="${S.interval}"
        style="width:100%;padding:0;background:none;border:none">
      <div class="hint">越快越实时，也越费电。建议走路 8 秒、宅家 30 秒。</div>
      <div class="hint" style="margin-top:6px;font-weight:700" id="quotaHint">今日剩余 ${quotaLeft()} 条</div>
      <div class="hint">只在真的移动时才发位置（静止时约 10 分钟一条保活）。免费通道每天上限 ${QUOTA_DAY} 条，快用完时会自动放慢，不会突然断掉。</div>
    </div>
    <div class="sw">
      <div class="k">记录轨迹<em>保存对方走过的路线</em></div>
      <input type="checkbox" id="swTrail" ${S.trail ? 'checked' : ''}>
    </div>
    <div class="sw">
      <div class="k">收到消息时通知我<em>需要先允许通知权限</em></div>
      <input type="checkbox" id="swNotify" ${S.notify ? 'checked' : ''}>
    </div>
    <div class="sw">
      <div class="k">提示音<em>她发消息时响一下</em></div>
      <input type="checkbox" id="swSound" ${S.sound ? 'checked' : ''}>
    </div>
    <div class="sw">
      <div class="k">接收 iPhone 后台补点<em>OwnTracks 格式的原始报文</em></div>
      <input type="checkbox" id="swOT" ${S.otrack !== false ? 'checked' : ''}>
    </div>
    <div class="note" style="margin-top:8px">
      网页切到后台后定位会被系统暂停 —— 这是手机的限制，不是应用坏了。<br><br>
      <b>安卓</b>：用我做的安卓版 App（带常驻服务），锁屏也一直更新。<br>
      <b>iPhone</b>：装免费的 <b>OwnTracks</b>，它能在后台持续上报位置。<br><br>
      设置路径：打开 OwnTracks → 右上角 <b>+</b> → 模式选 <b>HTTP</b> →
      地址填下面这行 → 其它保持默认即可。
      <div id="otUrl" style="margin-top:6px;padding:8px;border-radius:8px;background:rgba(0,0,0,.06);
        font-size:11px;word-break:break-all;line-height:1.5">${'https://ntfy.sh/' + (S.room ? topicOf(S.room) : '（先设置暗号）')}</div>
      <button class="btn sm line" id="btnOtCopy" style="margin-top:6px">复制这行地址</button>
      <div class="hint" style="margin-top:6px">
        后台补点走的是<b>未加密</b>通道（OwnTracks 本身不支持加密），
        但地址里的那一串就是你们的暗号，别人猜不到。介意就把上面的开关关掉。
      </div>
    </div>
  </div>

  <div class="card">
    <h4>${Kitty.heart('#FF6B9D', 13)} 外观</h4>
    <div class="sw"><div class="k">夜间模式<em>粉色星空</em></div>
      <input type="checkbox" id="swTheme" ${S.theme === 'night' ? 'checked' : ''}></div>
    <div class="sw"><div class="k">卫星地图</div>
      <input type="checkbox" id="swSat" ${S.layer === 'sat' ? 'checked' : ''}></div>
    <div class="k" style="padding:6px 0 8px">地图配色<em>矢量渲染 · 和高德 App 同一套</em></div>
    <div class="mchips" id="styleChips">
      ${MAP_STYLES.map(o => `<button class="mchip ${(S.mapStyle || 'macaron') === o[0] ? 'on' : ''}" data-s="${o[0]}">${o[1]}</button>`).join('')}
    </div>
    <div class="btngrid" style="margin-top:8px">
      <button class="btn sm ghost" id="btnDemo">${Kitty.glyph('eye', 15)} ${S.demo ? '关闭演示模式' : '看看演示效果'}</button>
      <button class="btn sm line" id="btnReset">重来一遍引导</button>
    </div>
  </div>

  <div class="card">
    <h4>${Kitty.glyph('lock', 13)} 关于隐私</h4>
    <div class="note">
      位置通过 <b>ntfy.sh</b> 公共服务器中转。开启加密后，服务器只能看到一串密文。
      本应用不上架、不收集任何数据，所有内容只存在你们两台手机上。
    </div>
    <div style="text-align:center;margin-top:12px;font-size:11px;color:var(--ink3)">
      ${Kitty.logo(22)}<br>两颗心 v1.0 · 只为你们两个人做的
    </div>
  </div>`;

  // 绑定
  $('#inName').onchange = e => { S.name = e.target.value.trim(); save(); if (me) upsertMe(me.lat, me.lng); pubPos(true); };
  // 暗号：边打边存 + 显式保存，不再只依赖 change（iOS 上失焦时机不可靠）
  let roomTimer = null;
  const commitRoom = v => {
    v = (v || '').trim();
    if (v === S.room) return;
    S.room = v; save(); peer = null; peerHistory = []; seenIds.clear();
    if (peerMarker) { map.removeLayer(peerMarker); peerMarker = null; }
    const ot = $('#otUrl');
    if (ot) ot.textContent = v ? ('https://ntfy.sh/' + topicOf(v)) : '（先设置暗号）';
    drawTrail(); renderPeer(); renderTrailPanel(); connect(); restartPub();
    toast(v ? '暗号已保存 ✓ 正在连接…' : '暗号已清空');
  };
  $('#inRoom').addEventListener('input', e => {
    clearTimeout(roomTimer);
    roomTimer = setTimeout(() => commitRoom(e.target.value), 900);
  });
  $('#inRoom').addEventListener('change', e => { clearTimeout(roomTimer); commitRoom(e.target.value); });
  $('#inRoom').addEventListener('focus', e => {
    // iOS 键盘会盖住底部输入框，聚焦后把它滚到中间
    setTimeout(() => { try { e.target.scrollIntoView({ block: 'center', behavior: 'smooth' }); } catch (x) {} }, 350);
  });
  $('#btnSaveRoom').onclick = () => { clearTimeout(roomTimer); commitRoom($('#inRoom').value); };
  $('#btnRand').onclick = () => {
    $('#inRoom').value = randRoom();
    $('#inRoom').dispatchEvent(new Event('change'));
  };
  $('#btnCopy').onclick = async () => {
    if (!S.room) return toast('先设置一个暗号');
    const txt = `💕 两颗心 · 实时定位\n打开：${location.href}\n暗号：${S.room}\n（把这个发给女朋友）`;
    try { await navigator.clipboard.writeText(txt); toast('已复制，直接粘贴发给她即可', true); }
    catch (e) { prompt('复制下面的内容发给她：', txt); }
  };
  $('#swEnc').onchange = e => { S.encrypt = e.target.checked; save(); toast(S.encrypt ? '已开启加密' : '已关闭加密（不推荐）'); };
  $('#inInt').oninput = e => { S.interval = +e.target.value;
    e.target.previousElementSibling.textContent = '位置更新频率：' + S.interval + ' 秒'; };
  $('#inInt').onchange = () => { save(); restartPub(); };
  $('#swTrail').onchange = e => { S.trail = e.target.checked; save(); drawTrail(); };
  $('#swNotify').onchange = async e => {
    if (e.target.checked && 'Notification' in window) {
      const p = await Notification.requestPermission();
      if (p !== 'granted') { e.target.checked = false; toast('系统没给通知权限'); }
    }
    S.notify = e.target.checked; save();
  };
  $('#swSound').onchange = e => { S.sound = e.target.checked; save(); };
  $('#swOT').onchange = e => {
    S.otrack = e.target.checked; save();
    toast(S.otrack ? '已开启：接收 iPhone 后台补点' : '已忽略后台补点');
  };
  $('#btnOtCopy').onclick = async () => {
    if (!S.room) return toast('先设置暗号');
    const u = 'https://ntfy.sh/' + topicOf(S.room);
    try { await navigator.clipboard.writeText(u); toast('已复制，粘到 OwnTracks 的地址栏', true); }
    catch (e) { prompt('复制下面这行：', u); }
  };
  $('#swTheme').onchange = e => { S.theme = e.target.checked ? 'night' : 'day'; save(); applyTheme(); };
  $('#swSat').onchange = e => { S.layer = e.target.checked ? 'sat' : 'std'; save(); applyLayer(); };
  $('#swHD') && ($('#swHD').onchange = e => { S.hd = e.target.checked; save(); applyLayer(); });
  const chips = $('#styleChips');
  if (chips) chips.addEventListener('click', e => {
    const b = e.target.closest('.mchip'); if (!b) return;
    S.mapStyle = b.dataset.s; save(); applyLayer();
    chips.querySelectorAll('.mchip').forEach(c => c.classList.toggle('on', c === b));
  });
  $('#btnDemo').onclick = () => { if (S.demo) stopDemo(); else startDemo(); renderMe(); };
  $('#btnReset').onclick = () => { if (confirm('重新走一遍引导？')) { openWelcome(); } };

  $$('#swatches .swatch').forEach(b => b.onclick = () => {
    S.avatar = { t: 'k', c: b.dataset.c }; save(); renderMe();
    if (me) upsertMe(me.lat, me.lng); pubPos(true);
  });
  $('#btnPhoto').onclick = () => $('#fileAv').click();
  $('#fileAv').onchange = e => {
    const f = e.target.files && e.target.files[0]; if (!f) return;
    const rd = new FileReader();
    rd.onload = () => {
      const img = new Image();
      img.onload = () => {
        const c = document.createElement('canvas'); c.width = c.height = 256;
        const s = Math.min(img.width, img.height);
        c.getContext('2d').drawImage(img, (img.width - s) / 2, (img.height - s) / 2, s, s, 0, 0, 256, 256);
        S.avatar = { t: 'p', data: c.toDataURL('image/jpeg', 0.82) };
        save(); renderMe(); if (me) upsertMe(me.lat, me.lng); pubPos(true);
        toast('头像已更换', true);
      };
      img.src = rd.result;
    };
    rd.readAsDataURL(f);
  };
}
function applyTheme() {
  const night = S.theme === 'night';
  document.documentElement.dataset.theme = night ? 'night' : 'day';
  if (amap) { try { amap.setMapStyle(mapStyleId()); } catch (e) {} }
  try { if (window.LKLX && LKLX.bars) LKLX.bars(night ? 'night' : 'day'); } catch (e) {}
}

/* 系统返回键：原生侧调用。返回 true = 我处理了（别退出），false = 交给系统退到桌面 */
window.lklxBack = function () {
  try {
    if ($('#welcome').classList.contains('on')) {
      if (step > 0) { step--; renderStep(); return true; }
      return false;
    }
    if ($('#sheet').classList.contains('up')) { $('#sheet').classList.remove('up'); return true; }
    const ov = document.querySelector('.overlay.on:not(#welcome)');
    if (ov) { ov.classList.remove('on'); return true; }
  } catch (e) {}
  return false;
};

/* ============ 12. 交互 ============ */
function focusPeer(up) {
  if (!peer) { toast('还没收到对方位置'); return; }
  if (up) map.flyTo([peer.lat, peer.lng], Math.max(map.getZoom(), 15), { duration: 0.8 });
  else map.setView([peer.lat, peer.lng]);
}
function bindUI() {
  // 面板展开/收起
  const sheet = $('#sheet');
  $('.grab').addEventListener('click', () => sheet.classList.toggle('up'));
  $('.peek').addEventListener('click', e => {
    if (e.target.closest('.pav')) { focusPeer(true); return; }
    sheet.classList.toggle('up');
  });
  $$('.tabs button').forEach(b => b.onclick = () => {
    $$('.tabs button').forEach(x => x.classList.toggle('on', x === b));
    $$('.panel').forEach(p => p.classList.toggle('on', p.id === 'panel' + b.dataset.tab));
    if (!$('#sheet').classList.contains('up')) $('#sheet').classList.add('up');
    if (b.dataset.tab === 'Trail') renderTrailPanel();
    if (b.dataset.tab === 'Me') renderMe();
    if (b.dataset.tab === 'Chat') renderChat();
  });
  const syncFabs = () => $('#fabs').classList.toggle('up', sheet.classList.contains('up'));
  new MutationObserver(syncFabs).observe(sheet, { attributes: true, attributeFilter: ['class'] });

  $('#btnLocate').onclick = () => {
    if (me) map.flyTo([me.lat, me.lng], 16, { duration: 0.7 });
    else askGeo();     // 没有位置时，这一步顺便当成「授权定位」的入口
  };
  $('#btnFit2').onclick = () => {
    const pts = []; if (me) pts.push([me.lat, me.lng]); if (peer) pts.push([peer.lat, peer.lng]);
    if (pts.length === 2) map.fitBounds(pts, { padding: [70, 110] });
    else if (pts.length === 1) map.setView(pts[0], 16);
  };
  $('#btnPokeFab').onclick = () => { sendPoke('想你啦 💕', true); };
  $('#btnTheme').onclick = () => { S.theme = S.theme === 'night' ? 'day' : 'night'; save(); applyTheme();
    renderMe(); toast(S.theme === 'night' ? '夜间模式' : '白天模式'); };

  // 快捷短语
  const QUICK = [
    ['想你啦 💕', true], ['在干嘛呀', false], ['吃饭了吗 🍚', false],
    ['注意安全哦', false], ['我到啦 📍', false], ['抱抱 🤗', true], ['早点睡 😴', false]
  ];
  $('#quick').innerHTML = QUICK.map((q, i) =>
    `<button data-i="${i}">${esc(q[0])}</button>`).join('');
  $$('#quick button').forEach(b => b.onclick = () => {
    const q = QUICK[+b.dataset.i];
    sendPoke(q[0], q[1]);
  });
  $('#btnSend').onclick = () => {
    const v = $('#inMsg').value.trim(); if (!v) return;
    $('#inMsg').value = ''; sendPoke(v, false, true);
  };
}
function sendPoke(text, hearts, plain) {
  if (!S.room) { toast('先在「我的」里设置房间暗号'); return; }
  chat.push({ me: true, text, t: Date.now() });
  renderChat();
  publish({ v: 1, k: 'msg', id: myId(), n: S.name || '我', msg: text, hearts: !!hearts, t: Date.now() });
  if (hearts) { heartsBurst(9); vibe(18); }
  if (plain) toast('已发送', true);
}

/* ============ 13. 引导 ============ */
let step = 0;
function openWelcome() {
  step = 0; renderStep();
  $('#welcome').classList.add('on');
}
function renderStep() {
  $$('.step').forEach((s, i) => s.classList.toggle('on', i === step));
  $$('.steps i').forEach((s, i) => s.classList.toggle('on', i <= step));
  if (step === 1) {
    $('#wvAvatars').innerHTML = ['#FF6B9D', '#F24E86', '#FF93B9', '#7FD8C4', '#FFC93D', '#9C7BFF'].map(c =>
      `<button class="swatch ${S.avatar.c === c && S.avatar.t !== 'p' ? 'on' : ''}" data-c="${c}">
        <span style="background:linear-gradient(140deg,${Kitty.lighten(c, 22)},${c})"></span></button>`).join('')
      + `<button class="swatch ${S.avatar.t === 'p' ? 'on' : ''}" id="wvPhoto"
           style="background:var(--p100)">${Kitty.glyph('eye', 18)}</button>`;
    $$('#wvAvatars .swatch[data-c]').forEach(b => b.onclick = () => {
      S.avatar = { t: 'k', c: b.dataset.c }; save(); renderStep();
      $('#wvPreview').innerHTML = Kitty.avatarHTML(S.avatar, 96);
    });
    $('#wvPhoto').onclick = () => $('#wvFile').click();
    $('#wvFile').onchange = e => {
      const f = e.target.files && e.target.files[0]; if (!f) return;
      const rd = new FileReader();
      rd.onload = () => {
        const img = new Image();
        img.onload = () => {
          const c = document.createElement('canvas'); c.width = c.height = 256;
          const s = Math.min(img.width, img.height);
          c.getContext('2d').drawImage(img, (img.width - s) / 2, (img.height - s) / 2, s, s, 0, 0, 256, 256);
          S.avatar = { t: 'p', data: c.toDataURL('image/jpeg', 0.82) };
          save(); renderStep(); $('#wvPreview').innerHTML = Kitty.avatarHTML(S.avatar, 96);
        };
        img.src = rd.result;
      };
      rd.readAsDataURL(f);
    };
    $('#wvPreview').innerHTML = Kitty.avatarHTML(S.avatar, 96);
    $('#wvName').value = S.name;
  }
  if (step === 2) {
    $('#wvRoom').value = S.room || randRoom();
  }
}
function bindWelcome() {
  $$('.wv-next').forEach(b => b.onclick = () => {
    if (step === 1) {
      const n = $('#wvName').value.trim();
      if (!n) { toast('给自己起个名字吧'); return; }
      S.name = n; save();
    }
    if (step === 2) { finishWelcome(); return; }
    step++; renderStep();
  });
  $$('.wv-back').forEach(b => b.onclick = () => { if (step > 0) { step--; renderStep(); } });
  $('#wvDemo').onclick = () => { $('#welcome').classList.remove('on'); startDemo();
    renderMe(); $('#sheet').classList.add('up');
    $$('.tabs button').forEach(x => x.classList.toggle('on', x.dataset.tab === 'Peer'));
    document.querySelector('.tabs button[data-tab="Peer"]').click(); };
  $('#wvRand').onclick = () => { $('#wvRoom').value = randRoom(); };
  $('#wvShare').onclick = async () => {
    const room = $('#wvRoom').value.trim();
    if (!room) { toast('先填一个暗号'); return; }
    const txt = `💕 两颗心 · 实时定位\n打开：${location.href}\n暗号：${room}`;
    try { await navigator.clipboard.writeText(txt); toast('已复制，发给她就好', true); }
    catch (e) { prompt('复制下面内容发给她：', txt); }
  };
  $('#wvGo').onclick = () => finishWelcome();
}
function finishWelcome() {
  const room = $('#wvRoom').value.trim();
  if (!room) { toast('暗号不能为空'); return; }
  S.room = room; S.welcome = true; save();
  $('#welcome').classList.remove('on');
  askGeo();     // 这一步带着点击手势，iOS 才会弹定位权限框
  connect(); catchUp(); restartPub();
  renderMe(); renderPeer();
  $('#sheet').classList.add('up');
  document.querySelector('.tabs button[data-tab="Peer"]').click();
  toast('开始共享位置 💕', true);
  heartsBurst(8);
}
function buildWelcome() {
  $('#welcome').innerHTML = `
  <div class="inner">
    <div class="steps"><i></i><i></i><i></i></div>

    <div class="step on">
      <div class="wel-hero">
        <span class="kitty">${Kitty.face({ bow: '#FF6B9D', w: 158, h: 138 })}</span>
        <h1>两颗心</h1>
        <div class="en">L I A N G &nbsp; K E &nbsp; X I N</div>
        <p>只属于你们两个人的地图<br>打开就能看到对方在哪，一直在一起 💕</p>
      </div>
      <div class="optlist">
        <div class="opt"><div class="oi">${Kitty.glyph('map', 20)}</div>
          <div class="ot"><b>真实地图</b><em>和地图软件一样的底图，街道、小区都看得清</em></div></div>
        <div class="opt"><div class="oi">${Kitty.heart('#FF4E8A', 20)}</div>
          <div class="ot"><b>实时看对方</b><em>距离、多久前更新、手机电量都能看到</em></div></div>
        <div class="opt"><div class="oi">${Kitty.glyph('lock', 20)}</div>
          <div class="ot"><b>只有你们看得懂</b><em>暗号当密钥加密，位置不上传给任何人</em></div></div>
      </div>
      <button class="btn wv-next" style="margin-top:14px">开始设置 ${Kitty.heart('#fff', 16)}</button>
      <button class="btn line" id="wvDemo" style="margin-top:9px">先看看效果（演示模式）</button>
    </div>

    <div class="step">
      <div class="wel-hero" style="margin-bottom:14px">
        <span class="kitty">${Kitty.heart('#FF4E8A', 54)}</span>
        <h1 style="font-size:23px">你是谁呀</h1>
        <p>这个头像会出现在她的地图上</p>
      </div>
      <div class="glasscard" style="text-align:center">
        <div id="wvPreview" style="display:inline-block;margin-bottom:14px"></div>
        <div class="swatches" id="wvAvatars" style="justify-content:center"></div>
        <input type="file" id="wvFile" accept="image/*" style="display:none">
        <div class="field" style="margin-top:16px;text-align:left">
          <label>我的昵称</label>
          <input id="wvName" maxlength="12" placeholder="例如 小笨蛋 / 宝贝">
        </div>
      </div>
      <div style="display:flex;gap:9px">
        <button class="btn ghost wv-back" style="flex:0 0 92px">上一步</button>
        <button class="btn wv-next">下一步</button>
      </div>
    </div>

    <div class="step">
      <div class="wel-hero" style="margin-bottom:14px">
        <span class="kitty">${Kitty.glyph('lock', 46, '#F24E86')}</span>
        <h1 style="font-size:23px">你们的暗号</h1>
        <p>两个人填一模一样的暗号<br>才能在地图上看到对方</p>
      </div>
      <div class="glasscard">
        <div class="field" style="margin-bottom:10px">
          <label>房间暗号</label>
          <input id="wvRoom" placeholder="kitty-xxxxxxxx">
          <div class="hint">点右边随机生成，然后原样发给她。<br>别改成 123456 这种，容易被别人猜到。</div>
        </div>
        <div class="btngrid">
          <button class="btn sm ghost" id="wvRand">换一个</button>
          <button class="btn sm ghost" id="wvShare">${Kitty.glyph('copy', 15)} 复制给她</button>
        </div>
      </div>
      <div style="display:flex;gap:9px">
        <button class="btn ghost wv-back" style="flex:0 0 92px">上一步</button>
        <button class="btn" id="wvGo">完成 💕</button>
      </div>
      <div class="footer-note">
        位置经 ntfy.sh 公共服务器加密中转 · 本体不上架商店<br>仅你们两人使用 · Hello Kitty 元素为本人手绘，非官方素材
      </div>
    </div>
  </div>`;
  bindWelcome();
}

/* ============ 14. 启动 ============ */
function checkBrowser() {
  if (!IN_APP_BROWSER) return;
  geoBar('<b>在「' + IN_APP_BROWSER + '」里没法定位</b>' +
    (IS_IOS ? '点右上角「…」→ 在 Safari 中打开；' : '点右上角「…」→ 在浏览器中打开；') +
    '或先复制网址，再粘到浏览器地址栏打开',
    '复制网址', () => copyUrl('网址已复制，粘到浏览器里打开'), 'warn');
}

function tick() {
  if (peer) renderPeer();
  if (nearWatch && peer && me && !nearWatch.fired) {
    const d = haversine(me, peer);
    if (d != null && d <= nearWatch.target) {
      nearWatch.fired = true;
      toast('💕 她就在 ' + (nearWatch.target < 1000 ? Math.round(nearWatch.target) + ' 米' : (nearWatch.target / 1000).toFixed(1) + ' 公里') + '内了！', true);
      heartsBurst(8); vibe([40, 60, 40]);
      if (S.notify && 'Notification' in window && Notification.permission === 'granted') {
        try { new Notification('💕 快到了', { body: '她已经在你附近啦', tag: 'near' }); } catch (e) {}
      }
    }
  }
}
function boot() {
  applyTheme();
  initMap();
  applyLayer();
  buildWelcome();
  $('#tabs').innerHTML = [
    ['Peer', 'map', '对方'], ['Trail', 'trail', '轨迹'],
    ['Chat', 'chat', '互动'], ['Me', 'me', '我的']
  ].map(t => `<button data-tab="${t[0]}" class="${t[0] === 'Peer' ? 'on' : ''}">
      ${Kitty.icon(t[1], 20)}<span>${t[2]}</span></button>`).join('');
  $('#panelChat').innerHTML = `
    <div class="card" style="display:flex;flex-direction:column">
      <h4>${Kitty.heart('#FF6B9D', 13)} 悄悄话</h4>
      <div class="chatbox" id="chatbox"></div>
      <div class="quickpokes" id="quick"></div>
      <div style="display:flex;gap:8px">
        <input id="inMsg" placeholder="说点什么…" maxlength="60"
          style="flex:1;padding:11px 14px;border-radius:14px;background:var(--p50);border:1.6px solid var(--line);font-size:14px">
        <button class="btn sm" id="btnSend" style="width:78px;flex:none">${Kitty.heart('#fff', 15)} 发送</button>
      </div>
    </div>
    <div class="note">每条消息都用你们的暗号加密后发送，公共服务器读不懂内容。</div>`;
  $('#fabs').innerHTML = `
    <button class="fab heart" id="btnPokeFab" title="戳一戳">${Kitty.heart('#fff', 24)}</button>
    <button class="fab" id="btnFit2" title="看全两个人">${Kitty.glyph('nav', 20)}</button>
    <button class="fab" id="btnTheme" title="夜间模式">${Kitty.glyph('eye', 20)}</button>
    <button class="fab" id="btnLocate" title="回到我的位置">${Kitty.glyph('gps', 20)}</button>`;
  bindUI();

  const savedTrail = load('lklx.trail');
  if (savedTrail && Array.isArray(savedTrail)) peerHistory = savedTrail;

  // 网页端存储空了（本地 HTTP 端口变了 / 清了缓存）就从原生配置补回来，不用重新输暗号
  if ((!S.room || !S.welcome) && hasNative()) {
    const n = nativeGet();
    if (n && n.room) {
      S.room = n.room;
      if (n.nm) S.name = n.nm;
      if (n.av) { try { S.avatar = JSON.parse(n.av) || S.avatar; } catch (e) {} }
      if (n.intv) S.interval = n.intv;
      S.welcome = true;
      save();
    }
  }

  renderChat(); renderPeer(); renderTrailPanel();

  if (!S.welcome || !S.room) {
    openWelcome();
    checkBrowser();
  } else {
    checkBrowser();
    startGeo(); connect(); catchUp(); restartPub();
  }
  setInterval(tick, 1000);
  if (navigator.wakeLock) {
    const lock = () => navigator.wakeLock.request('screen').catch(() => {});
    lock();
    document.addEventListener('visibilitychange', () => { if (!document.hidden) lock(); });
  }
  document.addEventListener('visibilitychange', () => { if (!document.hidden) { catchUp(); if (me) pubPos(true); } });
  window.addEventListener('online', () => { connect(); pubPos(true); });
}
if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
else boot();

})();
