#!/usr/bin/env node
/**
 * 两颗心 · 自建中转服务器
 * ---------------------------------------------------------------
 * 接口和 ntfy.sh 的最小可用子集完全一致，所以 App / 网页端一行都不用改，
 * 只要在「我的 → 服务器」里填上这台机器的地址就行：
 *
 *   POST /<topic>                 发一条消息（body 就是加密后的密文）
 *   GET  /<topic>/sse             订阅（Server-Sent Events 长连接）
 *   GET  /<topic>/json?poll=1     拉最近的历史消息（换行分隔的 JSON）
 *   GET  /healthz                 健康检查（网页端「测试连接」用的就是它）
 *
 * 特点：
 *   · 只有 Node 本身，没有任何第三方依赖（不用 npm install）
 *   · 每 12 小时清一次历史，内存占用可忽略；两个人用，实际峰值是几十 KB
 *   · 支持口令：设置 RELAY_TOKEN 后，发布/订阅都要带 Bearer 或 ?auth=
 *   · 密文原样转发，服务器看不到你们的位置（解密密钥是你们的暗号）
 *
 * 启动：  node server.js            （默认监听 8890）
 *         PORT=9000 RELAY_TOKEN=xxx node server.js
 */
'use strict';

const http = require('http');
const crypto = require('crypto');

const PORT = +(process.env.PORT || 8890);
const HOST = process.env.HOST || '0.0.0.0';
const TOKEN = process.env.RELAY_TOKEN || '';
const KEEP_MS = +(process.env.KEEP_MS || 12 * 3600 * 1000);  // 历史保留（默认 12 小时）
const MAX_PER_TOPIC = +(process.env.MAX_PER_TOPIC || 2000);  // 单个房间最多缓存多少条
const RATE_PER_MIN = +(process.env.RATE_PER_MIN || 600);     // 单 IP 每分钟最多几个请求（防扫）
const VERSION = '1.1.0';

/** topic -> [{id,time,event,topic,message}] */
const rooms = new Map();
/** topic -> Set<res> 活着的 SSE 连接 */
const streams = new Map();

function rid() {
  return crypto.randomBytes(9).toString('base64').replace(/[+/=]/g, '').slice(0, 12);
}
function ok(req, q) {
  if (!TOKEN) return true;
  const h = req.headers['authorization'] || '';
  if (h === 'Bearer ' + TOKEN || h === TOKEN) return true;
  return q && q.get('auth') === TOKEN;
}
/* ---- 单 IP 限速：放在公网上迟早被扫，挡一下基本的滥用 ---- */
const hits = new Map();     // ip -> {n, t}
function rateOk(ip) {
  const now = Date.now();
  let h = hits.get(ip);
  if (!h || now - h.t > 60000) { h = { n: 0, t: now }; hits.set(ip, h); }
  h.n++;
  return h.n <= RATE_PER_MIN;
}
setInterval(() => {
  const now = Date.now();
  for (const [ip, h] of hits) if (now - h.t > 120000) hits.delete(ip);
}, 300000).unref();

function json(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': '*',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Cache-Control': 'no-store'
  });
  res.end(body);
}

function addToRoom(topic, msg) {
  let list = rooms.get(topic);
  if (!list) { list = []; rooms.set(topic, list); }
  list.push(msg);
  if (list.length > MAX_PER_TOPIC) list.splice(0, list.length - MAX_PER_TOPIC);
  const subs = streams.get(topic);
  if (subs) {
    const line = 'data: ' + JSON.stringify(msg) + '\n\n';
    for (const s of subs) { try { s.write(line); } catch (e) { /* 断开的下次心跳会清掉 */ } }
  }
}

/* 定时清理过期历史 + 心跳 */
setInterval(() => {
  const cut = Date.now() - KEEP_MS;
  for (const [t, list] of rooms) {
    const keep = list.filter(m => m.time * 1000 >= cut);
    if (keep.length) rooms.set(t, keep); else rooms.delete(t);
  }
  for (const subs of streams.values()) {
    for (const s of subs) { try { s.write(': ping\n\n'); } catch (e) {} }
  }
}, 60000).unref();

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://x');
  const q = url.searchParams;
  const path = decodeURIComponent(url.pathname);

  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': '*',
      'Access-Control-Allow-Methods': 'GET,POST,OPTIONS'
    });
    return res.end();
  }

  if (path === '/healthz' || path === '/') {
    return json(res, 200, {
      ok: true, service: 'liangkeixin-relay', version: VERSION,
      rooms: rooms.size, token: TOKEN ? 1 : 0,
      uptime: Math.round(process.uptime())
    });
  }

  const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
    || req.socket.remoteAddress || '?';
  if (!rateOk(ip)) return json(res, 429, { error: 'too many requests' });

  const m = path.match(/^\/([^/]+?)(\/(sse|json))?$/);
  if (!m) return json(res, 404, { error: 'not found' });
  const topic = m[1];
  const sub = m[3] || '';
  if (!/^[-_A-Za-z0-9]{1,64}$/.test(topic)) {
    return json(res, 400, { error: 'topic 只能用字母数字和 - _，长度 1-64' });
  }

  // ---- 发布 ----
  if (req.method === 'POST') {
    if (!ok(req, q)) return json(res, 401, { error: 'unauthorized' });
    let body = '';
    req.on('data', c => {
      body += c;
      if (body.length > 2 * 1024 * 1024) { req.destroy(); }   // 位置就几百字节，照片会到几百 KB，上限 2MB
    });
    req.on('end', () => {
      if (!body) return json(res, 400, { error: 'empty body' });
      const msg = {
        id: rid(),
        time: Math.floor(Date.now() / 1000),
        event: 'message',
        topic,
        message: body
      };
      addToRoom(topic, msg);
      json(res, 200, msg);
    });
    return;
  }

  if (req.method !== 'GET') return json(res, 405, { error: 'method not allowed' });

  // ---- 订阅（SSE）----
  if (sub === 'sse') {
    if (!ok(req, q)) return json(res, 401, { error: 'unauthorized' });
    res.writeHead(200, {
      'Content-Type': 'text/event-stream; charset=utf-8',
      'Cache-Control': 'no-cache, no-transform',
      'Connection': 'keep-alive',
      'X-Accel-Buffering': 'no',        // 让 nginx 别缓冲，否则消息会被攒着不发
      'Access-Control-Allow-Origin': '*'
    });
    res.write(': connected\n\n');
    let subs = streams.get(topic);
    if (!subs) { subs = new Set(); streams.set(topic, subs); }
    subs.add(res);
    const bye = () => { subs.delete(res); if (!subs.size) streams.delete(topic); };
    req.on('close', bye);
    req.on('error', bye);
    return;
  }

  // ---- 拉历史 ----
  if (!ok(req, q)) return json(res, 401, { error: 'unauthorized' });
  const since = q.get('since') || '';
  let cut = 0;
  const hm = /^(\d+)([hmd])$/.exec(since);
  if (hm) cut = Date.now() - (+hm[1]) * ({ h: 3600000, m: 60000, d: 86400000 })[hm[2]];
  else if (/^\d+$/.test(since)) cut = +since * 1000;
  const list = (rooms.get(topic) || []).filter(x => x.time * 1000 >= cut);
  res.writeHead(200, {
    'Content-Type': 'application/x-ndjson; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Cache-Control': 'no-store'
  });
  res.end(list.map(x => JSON.stringify(x)).join('\n'));
});

server.listen(PORT, HOST, () => {
  console.log('[relay] 两颗心中转 v' + VERSION + ' → http://' + HOST + ':' + PORT
    + (TOKEN ? '  (需要口令)' : '  (不校验口令)'));
});

/* 优雅退出：把长连接放掉，别让 systemd 等到超时 */
function bye() {
  console.log('[relay] 退出中…');
  for (const subs of streams.values()) for (const s of subs) { try { s.end(); } catch (e) {} }
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 3000).unref();
}
process.on('SIGTERM', bye);
process.on('SIGINT', bye);
