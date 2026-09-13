/* ===========================================================
   两颗心 · Hello Kitty 风格素材生成器
   全部图形手写 SVG，不依赖任何外部图片
   =========================================================== */
const Kitty = (function () {
  const LINE = '#4A2530';

  /* ---------- 猫脸 ---------- */
  function face(o) {
    o = o || {};
    const skin  = o.skin  || '#FFFFFF';
    const bow   = o.bow   || '#FF6B9D';
    const bowD  = o.bowDark || shade(bow, -18);
    const blush = o.blush === false ? 'none' : (o.blushColor || '#FFB3CC');
    const w     = o.w || 110, h = o.h || 96;
    const sw    = o.stroke === false ? 0 : (o.strokeW || 0);

    return `
<svg viewBox="0 0 110 96" width="${w}" height="${h}" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="kf${uid()}" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0%" stop-color="#FFFFFF"/>
      <stop offset="100%" stop-color="${shade(skin,-5)}"/>
    </linearGradient>
  </defs>
  <!-- 耳朵 -->
  <path d="M18,46 L13,12 L52,30 Z" fill="url(#kf${uid(0)})" stroke="${line(sw)}" stroke-width="${sw}" stroke-linejoin="round"/>
  <path d="M92,46 L97,12 L58,30 Z" fill="url(#kf${uid(0)})" stroke="${line(sw)}" stroke-width="${sw}" stroke-linejoin="round"/>
  <!-- 蝴蝶结（她的左耳，观众右耳） -->
  <g transform="rotate(-6 88 15)">
    <ellipse cx="78" cy="14" rx="10" ry="8.2" fill="${bow}" transform="rotate(-22 78 14)"/>
    <ellipse cx="98" cy="12" rx="10" ry="8.2" fill="${bowD}" transform="rotate(22 98 12)"/>
    <circle cx="88" cy="14" r="5.4" fill="${bow}" stroke="#fff" stroke-width="1.2"/>
  </g>
  <!-- 头 -->
  <ellipse cx="55" cy="57" rx="43" ry="36" fill="url(#kf${uid(0)})"/>
  <!-- 腮红 -->
  ${blush === 'none' ? '' : `
  <ellipse cx="25" cy="70" rx="7.5" ry="5" fill="${blush}" opacity="0.55"/>
  <ellipse cx="85" cy="70" rx="7.5" ry="5" fill="${blush}" opacity="0.55"/>`}
  <!-- 眼睛 -->
  <ellipse cx="38" cy="55" rx="4.7" ry="6.2" fill="${LINE}"/>
  <ellipse cx="72" cy="55" rx="4.7" ry="6.2" fill="${LINE}"/>
  <circle cx="39.6" cy="52.8" r="1.5" fill="#fff" opacity="0.9"/>
  <circle cx="73.6" cy="52.8" r="1.5" fill="#fff" opacity="0.9"/>
  <!-- 鼻子 -->
  <ellipse cx="55" cy="66" rx="6.4" ry="4.8" fill="#FFC93D"/>
  <!-- 胡须 -->
  <g stroke="${LINE}" stroke-width="2.7" stroke-linecap="round" opacity="0.9">
    <line x1="8"  y1="46" x2="28" y2="51"/>
    <line x1="6"  y1="58" x2="27" y2="59"/>
    <line x1="8"  y1="70" x2="28" y2="67"/>
    <line x1="102" y1="46" x2="82" y2="51"/>
    <line x1="104" y1="58" x2="83" y2="59"/>
    <line x1="102" y1="70" x2="82" y2="67"/>
  </g>
</svg>`;
  }

  /* ---------- 心 ---------- */
  function heart(color, size) {
    color = color || '#FF6B9D'; size = size || 24;
    return `<svg viewBox="0 0 32 30" width="${size}" height="${size * 30 / 32}" xmlns="http://www.w3.org/2000/svg">
      <path d="M16,28 C16,28 2,19.2 2,10.6 C2,5.6 5.9,2 10.4,2 C12.9,2 15,3.2 16,5 C17,3.2 19.1,2 21.6,2 C26.1,2 30,5.6 30,10.6 C30,19.2 16,28 16,28 Z"
        fill="${color}"/>
    </svg>`;
  }

  /* ---------- 两颗心 logo ---------- */
  function logo(size) {
    size = size || 30;
    return `<svg viewBox="0 0 40 34" width="${size}" height="${size * 34 / 40}" xmlns="http://www.w3.org/2000/svg">
      <path d="M13,31 C13,31 1,22.6 1,14.4 C1,9.6 4.7,6 8.9,6 C11.3,6 13.3,7.2 14,9 C14.7,7.2 16.7,6 19.1,6 C23.3,6 27,9.6 27,14.4 C27,22.6 13,31 13,31 Z" fill="#FF9EC1"/>
      <path d="M27,33 C27,33 15,24.6 15,16.4 C15,11.6 18.7,8 22.9,8 C25.3,8 27.3,9.2 28,11 C28.7,9.2 30.7,8 33.1,8 C37.3,8 41,11.6 41,16.4 C41,24.6 27,33 27,33 Z"
        fill="#FF4E8A" transform="translate(-2,-2) scale(0.94)"/>
    </svg>`;
  }

  /* ---------- 底部导航图标 ---------- */
  const PATHS = {
    map:   '<path d="M12 21s7-6.2 7-11a7 7 0 1 0-14 0c0 4.8 7 11 7 11z"/><circle cx="12" cy="10" r="2.6"/>',
    trail: '<path d="M4 18c3.5 0 3.5-5 7-5s3.5 5 7 5"/><circle cx="4" cy="18" r="1.8"/><circle cx="18" cy="18" r="1.8"/><circle cx="20" cy="6" r="1.8"/>',
    chat:  '<path d="M20.5 12.2c0 3.9-3.8 7-8.5 7-1 0-2-.15-2.9-.42L4.5 20.5l1.2-3.2A6.7 6.7 0 0 1 3.5 12.2c0-3.9 3.8-7 8.5-7s8.5 3.1 8.5 7z"/>',
    me:    '<circle cx="12" cy="8.5" r="3.8"/><path d="M4.8 20c0-3.6 3.2-6 7.2-6s7.2 2.4 7.2 6"/>'
  };
  function icon(name, size, stroke) {
    size = size || 24; stroke = stroke || 'currentColor';
    return `<svg viewBox="0 0 24 24" width="${size}" height="${size}" fill="none"
      stroke="${stroke}" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">
      ${PATHS[name] || ''}</svg>`;
  }

  /* ---------- 小图标 ---------- */
  function glyph(name, size, color) {
    size = size || 18; color = color || '#FF4E8A';
    const g = {
      battery: '<rect x="2" y="7" width="16" height="10" rx="2.5"/><rect x="19" y="10" width="2.6" height="4" rx="1.2" fill="CUR"/>',
      clock:   '<circle cx="12" cy="12" r="9"/><path d="M12 7.2V12l3.2 2"/>',
      speed:   '<path d="M4 18a8 8 0 1 1 16 0"/><path d="M12 18 16.5 11"/>',
      gps:     '<circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3"/>',
      nav:     '<path d="M20 4 11 21l-1.6-7.4L2 12z"/>',
      poke:    '<path d="M12 21s-7-4.6-7-9.6C5 8.4 7.1 6.4 9.7 6.4c1.4 0 2.7.7 3.3 1.8.6-1.1 1.9-1.8 3.3-1.8 2.6 0 4.7 2 4.7 5 0 5-7 9.6-7 9.6z"/>',
      sos:     '<path d="M12 3 2.5 20h19z"/><path d="M12 9.5v5M12 17.2v.1"/>',
      lock:    '<rect x="4.5" y="10" width="15" height="10.5" rx="2.5"/><path d="M8 10V7.5a4 4 0 0 1 8 0V10"/>',
      copy:    '<rect x="8.5" y="8.5" width="11" height="11" rx="2.5"/><path d="M15.5 8.5v-1a2.5 2.5 0 0 0-2.5-2.5H6a2.5 2.5 0 0 0-2.5 2.5V13a2.5 2.5 0 0 0 2.5 2.5h1"/>',
      check:   '<path d="M4.5 12.5 9.5 17.5 19.5 6.5"/>',
      gear:    '<circle cx="12" cy="12" r="3.2"/><path d="M19.4 15a1.6 1.6 0 0 0 .32 1.77l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06A1.6 1.6 0 0 0 15 19.4a1.6 1.6 0 0 0-1 1.47V21a2 2 0 1 1-4 0v-.1A1.6 1.6 0 0 0 9 19.4a1.6 1.6 0 0 0-1.77.32l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.6 1.6 0 0 0 4.6 15a1.6 1.6 0 0 0-1.47-1H3a2 2 0 1 1 0-4h.1A1.6 1.6 0 0 0 4.6 9a1.6 1.6 0 0 0-.32-1.77l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.6 1.6 0 0 0 9 4.6a1.6 1.6 0 0 0 1-1.47V3a2 2 0 1 1 4 0v.1A1.6 1.6 0 0 0 15 4.6a1.6 1.6 0 0 0 1.77-.32l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.6 1.6 0 0 0 19.4 9v0a1.6 1.6 0 0 0 1.47 1H21a2 2 0 1 1 0 4h-.1a1.6 1.6 0 0 0-1.47 1z"/>',
      layers:  '<path d="M12 3 3 8l9 5 9-5z"/><path d="M3 13l9 5 9-5"/>',
      trash:   '<path d="M4 7h16M9 7V5.2A1.2 1.2 0 0 1 10.2 4h3.6A1.2 1.2 0 0 1 15 5.2V7M6.5 7l1 12.2A1.8 1.8 0 0 0 9.3 21h5.4a1.8 1.8 0 0 0 1.8-1.8L17.5 7"/>',
      bell:    '<path d="M6 9a6 6 0 1 1 12 0c0 4 1.5 5.5 1.5 5.5h-15S6 13 6 9z"/><path d="M10 18a2 2 0 0 0 4 0"/>',
      eye:     '<path d="M2.5 12S6 6 12 6s9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6z"/><circle cx="12" cy="12" r="2.8"/>'
    }[name] || '';
    return `<svg viewBox="0 0 24 24" width="${size}" height="${size}" fill="none"
      stroke="${color}" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">
      ${g.replace('CUR', color)}</svg>`;
  }

  /* ---------- 地图头像标记 ---------- */
  function markerHTML(name, avatar, opts) {
    opts = opts || {};
    const av = avatarHTML(avatar, opts.size || 52);
    return `<div class="mk ${opts.me ? 'me' : 'peer'}">
      <div class="mk-halo"></div>
      <div class="mk-av" style="--ring:${opts.ring || '#FF6B9D'}">${av}</div>
      <div class="mk-tail"></div>
      <div class="mk-tag">${esc(name)}${opts.me && name && name !== '我' ? ' · 我' : ''}</div>
    </div>`;
  }

  function avatarHTML(avatar, size) {
    size = size || 52;
    avatar = avatar || {};
    // 兼容两种命名：{t:'p',data}/{t:'k',c} 与 {type:'photo',data}/{color}
    const kind = avatar.t || avatar.type;
    const data = avatar.data;
    const col = avatar.c || avatar.color;
    if ((kind === 'p' || kind === 'photo') && data) {
      return `<img class="av-img" src="${data}" alt=""
        style="width:${size}px;height:${size}px">`;
    }
    const bow = col || '#FF6B9D';
    return `<span class="av-svg" style="width:${size}px;height:${size}px">${face({ bow: bow, w: size, h: size * 0.87 })}</span>`;
  }

  /* ---------- 工具 ---------- */
  let _uid = 0;
  function uid(reset) { if (reset === 0) { _uid = 0; } return '_' + (_uid++); }
  function line(sw) { return sw > 0 ? '#F2C6D8' : 'none'; }
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, c =>
      ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }
  function shade(hex, amt) {
    hex = hex.replace('#', '');
    if (hex.length === 3) hex = hex.split('').map(c => c + c).join('');
    let r = parseInt(hex.slice(0, 2), 16), g = parseInt(hex.slice(2, 4), 16), b = parseInt(hex.slice(4, 6), 16);
    const f = v => Math.max(0, Math.min(255, Math.round(v + amt)));
    return '#' + [f(r), f(g), f(b)].map(v => v.toString(16).padStart(2, '0')).join('');
  }
  function lighten(hex, p) { return shade(hex, 255 * p / 100); }

  return { face, heart, logo, icon, glyph, markerHTML, avatarHTML, esc, shade, lighten, LINE };
})();
