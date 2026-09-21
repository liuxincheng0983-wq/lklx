/* ===========================================================
   两颗心 · 二维码生成（零依赖，纯手写）
   -----------------------------------------------------------
   只做一件事：把一段文字（你们的房间号 / 服务器地址 / 口令）
   画成能扫的二维码。这样「她」不用手打，扫一下就把配置接过去了。

   支持的纠错级别：L / M / Q / H，版本 1–40 自动选。
   对外： KittyQR.matrix(text, 'M')  → 布尔二维数组（true = 黑）
         KittyQR.draw(canvas, text, {size, ec, margin})
   =========================================================== */
(function (root) {
  'use strict';

  /* 每个版本 4 个纠错级别（L,M,Q,H）的 RS 分块表。
     每项是若干个三元组 [块数, 每块总码字, 每块数据码字]，
     有两个分组时就是 6 个数（比如 version 5-Q）。 */
  const RS_TABLE = [
    [1,26,19],[1,26,16],[1,26,13],[1,26,9],
    [1,44,34],[1,44,28],[1,44,22],[1,44,16],
    [1,70,55],[1,70,44],[2,35,17],[2,35,13],
    [1,100,80],[2,50,32],[2,50,24],[4,25,9],
    [1,134,108],[2,67,43],[2,33,15,2,34,16],[2,33,11,2,34,12],
    [2,86,68],[4,43,27],[4,43,19],[4,43,15],
    [2,98,78],[4,49,31],[2,32,14,4,33,15],[4,39,13,1,40,14],
    [2,121,97],[2,60,38,2,61,39],[4,40,18,2,41,19],[4,40,14,2,41,15],
    [2,146,116],[3,58,36,2,59,37],[4,36,16,4,37,17],[4,36,12,4,37,13],
    [2,86,68,2,87,69],[4,69,43,1,70,44],[6,43,19,2,44,20],[6,43,15,2,44,16],
    [4,101,81],[1,80,50,4,81,51],[4,50,22,4,51,23],[3,36,12,8,37,13],
    [2,116,92,2,117,93],[6,58,36,2,59,37],[4,46,20,6,47,21],[7,42,14,4,43,15],
    [4,133,107],[8,59,37,1,60,38],[8,44,20,4,45,21],[12,33,11,4,34,12],
    [3,145,115,1,146,116],[4,64,40,5,65,41],[11,36,16,5,37,17],[11,36,12,5,37,13],
    [5,109,87,1,110,88],[5,65,41,5,66,42],[5,54,24,7,55,25],[11,36,12,7,37,13],
    [5,122,98,1,123,99],[7,73,45,3,74,46],[15,43,19,2,44,20],[3,45,15,13,46,16],
    [1,135,107,5,136,108],[10,74,46,1,75,47],[1,50,22,15,51,23],[2,42,14,17,43,15],
    [5,150,120,1,151,121],[9,69,43,4,70,44],[17,50,22,1,51,23],[2,42,14,19,43,15],
    [3,141,113,4,142,114],[3,70,44,11,71,45],[17,47,21,4,48,22],[9,39,13,16,40,14],
    [3,135,107,5,136,108],[3,67,41,13,68,42],[15,54,24,5,55,25],[15,43,15,10,44,16],
    [4,144,116,4,145,117],[17,68,42],[17,50,22,6,51,23],[19,46,16,6,47,17],
    [2,139,111,7,140,112],[17,74,46],[7,54,24,16,55,25],[34,37,13],
    [4,151,121,5,152,122],[4,75,47,14,76,48],[11,54,24,14,55,25],[16,45,15,14,46,16],
    [6,147,117,4,148,118],[6,73,45,14,74,46],[11,54,24,16,55,25],[30,46,16,2,47,17],
    [8,132,106,4,133,107],[8,75,47,13,76,48],[7,54,24,22,55,25],[22,45,15,13,46,16],
    [10,142,114,2,143,115],[19,74,46,4,75,47],[28,50,22,6,51,23],[33,46,16,4,47,17],
    [8,152,122,4,153,123],[22,73,45,3,74,46],[8,53,23,26,54,24],[12,45,15,28,46,16],
    [3,147,117,10,148,118],[3,73,45,23,74,46],[4,54,24,31,55,25],[11,45,15,31,46,16],
    [7,146,116,7,147,117],[21,73,45,7,74,46],[1,53,23,37,54,24],[19,45,15,26,46,16],
    [5,145,115,10,146,116],[19,75,47,10,76,48],[15,54,24,25,55,25],[23,45,15,25,46,16],
    [13,145,115,3,146,116],[2,74,46,29,75,47],[42,54,24,1,55,25],[23,45,15,28,46,16],
    [17,145,115],[10,74,46,23,75,47],[10,54,24,35,55,25],[19,45,15,35,46,16],
    [17,145,115,1,146,116],[14,74,46,21,75,47],[29,54,24,19,55,25],[11,45,15,46,46,16],
    [13,145,115,6,146,116],[14,74,46,23,75,47],[44,54,24,7,55,25],[59,46,16,1,47,17],
    [12,151,121,7,152,122],[12,75,47,26,76,48],[39,54,24,14,55,25],[22,45,15,41,46,16],
    [6,151,121,14,152,122],[6,75,47,34,76,48],[46,54,24,10,55,25],[2,45,15,64,46,16],
    [17,152,122,4,153,123],[29,74,46,14,75,47],[49,54,24,10,55,25],[24,45,15,46,46,16],
    [4,152,122,18,153,123],[13,74,46,32,75,47],[48,54,24,14,55,25],[42,45,15,32,46,16],
    [20,147,117,4,148,118],[40,75,47,7,76,48],[43,54,24,22,55,25],[10,45,15,67,46,16],
    [19,148,118,6,149,119],[18,75,47,31,76,48],[34,54,24,34,55,25],[20,45,15,61,46,16],
  ];
  const EC_IDX = { L: 0, M: 1, Q: 2, H: 3 };

  /* ---- GF(256)：二维码用的是 0x11D 本原多项式 ---- */
  const EXP = new Uint8Array(512), LOG = new Uint8Array(256);
  (function () {
    let x = 1;
    for (let i = 0; i < 255; i++) { EXP[i] = x; LOG[x] = i; x <<= 1; if (x & 0x100) x ^= 0x11d; }
    for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
  })();
  const mul = (a, b) => (a === 0 || b === 0) ? 0 : EXP[LOG[a] + LOG[b]];

  function genPoly(n) {
    let p = [1];
    for (let i = 0; i < n; i++) {
      const np = new Array(p.length + 1).fill(0);
      for (let j = 0; j < p.length; j++) {
        np[j] ^= mul(p[j], EXP[i]);
        np[j + 1] ^= p[j];
      }
      p = np;
    }
    /* 上面按「次数从低到高」堆出来的，标准写法是从最高次往下排，转过来 */
    return p.reverse();
  }
  function rsEncode(data, ecLen) {
    const gen = genPoly(ecLen);
    const res = new Array(ecLen).fill(0);
    for (let k = 0; k < data.length; k++) {
      const factor = data[k] ^ res[0];
      res.shift(); res.push(0);
      if (factor) for (let i = 0; i < ecLen; i++) res[i] ^= mul(gen[i + 1], factor);
    }
    return res;
  }

  function utf8(str) {
    const out = [];
    for (let i = 0; i < str.length; i++) {
      let c = str.codePointAt(i);
      if (c > 0xffff) i++;
      if (c < 0x80) out.push(c);
      else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 63));
      else if (c < 0x10000) out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
      else out.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 63), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
    }
    return out;
  }

  function blocks(version, ec) {
    const e = RS_TABLE[(version - 1) * 4 + EC_IDX[ec]];
    const out = [];
    for (let i = 0; i < e.length; i += 3) {
      for (let k = 0; k < e[i]; k++) out.push({ total: e[i + 1], data: e[i + 2] });
    }
    return out;
  }
  function dataCapacity(version, ec) {
    return blocks(version, ec).reduce((s, b) => s + b.data, 0);
  }

  /* ---- 选版本 + 编码成比特流 ---- */
  function encodeData(text, ec) {
    const bytes = utf8(text);
    let version = 0;
    for (let v = 1; v <= 40; v++) {
      const countBits = v < 10 ? 8 : 16;
      const need = Math.ceil((4 + countBits + bytes.length * 8) / 8);
      if (need <= dataCapacity(v, ec)) { version = v; break; }
    }
    if (!version) throw new Error('内容太长，二维码装不下');
    const countBits = version < 10 ? 8 : 16;
    const bits = [];
    const push = (val, len) => { for (let i = len - 1; i >= 0; i--) bits.push((val >> i) & 1); };
    push(4, 4);                       // 字节模式
    push(bytes.length, countBits);
    bytes.forEach(b => push(b, 8));
    const cap = dataCapacity(version, ec) * 8;
    for (let i = 0; i < 4 && bits.length < cap; i++) bits.push(0);   // 结束符
    while (bits.length % 8) bits.push(0);
    const pad = [0xEC, 0x11];
    for (let i = 0; bits.length < cap; i++) push(pad[i % 2], 8);

    /* 拆块 → 算纠错 → 交错 */
    const bs = blocks(version, ec);
    const words = [];
    for (let i = 0; i < bits.length; i += 8) {
      let b = 0; for (let j = 0; j < 8; j++) b = (b << 1) | bits[i + j];
      words.push(b);
    }
    const dBlocks = [], eBlocks = [];
    let pos = 0;
    for (const b of bs) {
      const d = words.slice(pos, pos + b.data); pos += b.data;
      dBlocks.push(d);
      eBlocks.push(rsEncode(d, b.total - b.data));
    }
    const out = [];
    const maxD = Math.max(...dBlocks.map(b => b.length));
    for (let i = 0; i < maxD; i++) for (const b of dBlocks) if (i < b.length) out.push(b[i]);
    const maxE = Math.max(...eBlocks.map(b => b.length));
    for (let i = 0; i < maxE; i++) for (const b of eBlocks) if (i < b.length) out.push(b[i]);
    return { version, code: out };
  }

  /* ---- 矩阵 ---- */
  function alignPos(version) {
    if (version === 1) return [];
    const n = Math.floor(version / 7) + 2;
    const size = version * 4 + 17;
    const step = Math.ceil((size - 13) / (2 * n - 2)) * 2;
    const pos = [6];
    for (let i = n - 1; i >= 1; i--) pos.push(size - 7 - (n - 1 - i) * step);
    return pos;
  }
  function maskFn(m, i, j) {
    switch (m) {
      case 0: return (i + j) % 2 === 0;
      case 1: return i % 2 === 0;
      case 2: return j % 3 === 0;
      case 3: return (i + j) % 3 === 0;
      case 4: return (Math.floor(i / 2) + Math.floor(j / 3)) % 2 === 0;
      case 5: return ((i * j) % 2) + ((i * j) % 3) === 0;
      case 6: return (((i * j) % 2) + ((i * j) % 3)) % 2 === 0;
      default: return (((i + j) % 2) + ((i * j) % 3)) % 2 === 0;
    }
  }
  function fmtBits(ec, mask) {
    const ecl = [1, 0, 3, 2][EC_IDX[ec]];      // 格式信息里的级别编号
    let d = (ecl << 3) | mask;
    let v = d << 10;
    for (let i = 4; i >= 0; i--) if ((v >> (10 + i)) & 1) v ^= 0x537 << i;
    return ((d << 10) | v) ^ 0x5412;
  }
  function verBits(version) {
    let v = version << 12;
    for (let i = 5; i >= 0; i--) if ((v >> (12 + i)) & 1) v ^= 0x1f25 << i;
    return (version << 12) | v;
  }

  function build(version, code, ec, mask) {
    const size = version * 4 + 17;
    const m = [], fixed = [];
    for (let i = 0; i < size; i++) { m.push(new Array(size).fill(false)); fixed.push(new Array(size).fill(false)); }
    const set = (r, c, v) => { if (r >= 0 && r < size && c >= 0 && c < size) { m[r][c] = v; fixed[r][c] = true; } };
    const finder = (r0, c0) => {
      for (let r = -1; r <= 7; r++) for (let c = -1; c <= 7; c++) {
        const rr = r0 + r, cc = c0 + c;
        if (rr < 0 || rr >= size || cc < 0 || cc >= size) continue;
        const on = (r >= 0 && r <= 6 && (c === 0 || c === 6)) ||
                   (c >= 0 && c <= 6 && (r === 0 || r === 6)) ||
                   (r >= 2 && r <= 4 && c >= 2 && c <= 4);
        set(rr, cc, on);
      }
    };
    finder(0, 0); finder(0, size - 7); finder(size - 7, 0);
    for (let i = 8; i < size - 8; i++) { set(6, i, i % 2 === 0); set(i, 6, i % 2 === 0); }
    const ap = alignPos(version);
    for (const r of ap) for (const c of ap) {
      if ((r === 6 && c === 6) || (r === 6 && c === size - 7) || (r === size - 7 && c === 6)) continue;
      for (let dr = -2; dr <= 2; dr++) for (let dc = -2; dc <= 2; dc++) {
        const on = Math.max(Math.abs(dr), Math.abs(dc)) !== 1;
        set(r + dr, c + dc, on);
      }
    }
    set(size - 8, 8, true);                       // 固定黑点
    for (let i = 0; i < 9; i++) { if (i !== 6) { set(8, i, false); set(i, 8, false); } }
    for (let i = 0; i < 8; i++) { set(8, size - 8 + i, false); set(size - 8 + i, 8, false); }
    if (version >= 7) {
      const vb = verBits(version);
      for (let i = 0; i < 18; i++) {
        const b = ((vb >> i) & 1) === 1;
        set(Math.floor(i / 3), size - 11 + (i % 3), b);
        set(size - 11 + (i % 3), Math.floor(i / 3), b);
      }
    }
    /* 格式信息：两份，摆放位置是 (行,列) —— 别写成转置了，写反了扫码器认不出 */
    const fb = fmtBits(ec, mask);
    for (let i = 0; i < 15; i++) {
      const b = ((fb >> i) & 1) === 1;
      if (i < 6) set(i, 8, b);              // 左上竖
      else if (i < 8) set(i + 1, 8, b);
      else if (i === 8) set(8, 7, b);       // 左上横
      else set(8, 14 - i, b);
      if (i < 8) set(8, size - 1 - i, b);   // 右上横
      else set(size - 15 + i, 8, b);        // 左下竖
    }
    set(size - 8, 8, true);

    /* 数据按 Z 字形填 */
    let idx = 0, dir = -1, row = size - 1;
    for (let col = size - 1; col > 0; col -= 2) {
      if (col === 6) col--;
      for (;;) {
        for (let c = 0; c < 2; c++) {
          const cc = col - c;
          if (!fixed[row][cc]) {
            let dark = false;
            if (idx < code.length * 8) {
              dark = ((code[idx >> 3] >> (7 - (idx & 7))) & 1) === 1;
              idx++;
            }
            if (maskFn(mask, row, cc)) dark = !dark;
            m[row][cc] = dark;
          }
        }
        row += dir;
        if (row < 0 || row >= size) { row -= dir; dir = -dir; break; }
      }
    }
    return m;
  }

  function penalty(m) {
    const n = m.length;
    let p = 0;
    const runScore = (line) => {
      let s = 0, run = 1;
      for (let i = 1; i < line.length; i++) {
        if (line[i] === line[i - 1]) run++;
        else { if (run >= 5) s += 3 + (run - 5); run = 1; }
      }
      if (run >= 5) s += 3 + (run - 5);
      return s;
    };
    for (let i = 0; i < n; i++) { p += runScore(m[i]); p += runScore(m.map(r => r[i])); }
    for (let r = 0; r < n - 1; r++) for (let c = 0; c < n - 1; c++) {
      const v = m[r][c];
      if (v === m[r][c + 1] && v === m[r + 1][c] && v === m[r + 1][c + 1]) p += 3;
    }
    const pat = [true, false, true, true, true, false, true, false, false, false, false];
    const patR = [false, false, false, false, true, false, true, true, true, false, true];
    const has = (arr, i, t) => t.every((v, k) => arr[i + k] === v);
    for (let i = 0; i < n; i++) {
      const row = m[i], col = m.map(r => r[i]);
      for (let j = 0; j <= n - 11; j++) {
        if (has(row, j, pat) || has(row, j, patR)) p += 40;
        if (has(col, j, pat) || has(col, j, patR)) p += 40;
      }
    }
    let dark = 0;
    for (const row of m) for (const v of row) if (v) dark++;
    const pct = dark * 100 / (n * n);
    p += Math.floor(Math.abs(pct - 50) / 5) * 10;
    return p;
  }

  /** 返回布尔二维数组（true = 黑） */
  function matrix(text, ec, forceMask) {
    ec = EC_IDX[ec] != null ? ec : 'M';
    const { version, code } = encodeData(text, ec);
    if (forceMask != null) return build(version, code, ec, forceMask);
    let best = null, bestScore = Infinity;
    for (let mask = 0; mask < 8; mask++) {
      const m = build(version, code, ec, mask);
      const s = penalty(m);
      if (s < bestScore) { bestScore = s; best = m; }
    }
    return best;
  }

  /** 画到 canvas 上（自动按 devicePixelRatio 放大，扫得清楚） */
  function draw(canvas, text, opt) {
    opt = opt || {};
    const m = matrix(text, opt.ec || 'M');
    const n = m.length;
    const margin = opt.margin == null ? 4 : opt.margin;
    const total = n + margin * 2;
    const cssSize = opt.size || 240;
    const dpr = Math.min(3, root.devicePixelRatio || 1);
    canvas.width = Math.round(cssSize * dpr);
    canvas.height = Math.round(cssSize * dpr);
    canvas.style.width = cssSize + 'px';
    canvas.style.height = cssSize + 'px';
    const ctx = canvas.getContext('2d');
    const scale = canvas.width / total;
    ctx.fillStyle = opt.bg || '#FFFFFF';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = opt.fg || '#221016';
    for (let r = 0; r < n; r++) {
      for (let c = 0; c < n; c++) {
        if (!m[r][c]) continue;
        ctx.fillRect(Math.round((c + margin) * scale), Math.round((r + margin) * scale),
          Math.ceil(scale), Math.ceil(scale));
      }
    }
    return m;
  }

  const api = { matrix, draw, version: '1.0', _code: (t, e) => encodeData(t, e || 'M') };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.KittyQR = api;
})(typeof self !== 'undefined' ? self : this);
