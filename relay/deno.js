/**
 * 两颗心 · 中转服务器（Deno Deploy 版）
 * ---------------------------------------------------------------
 * 不想买服务器的话用这个 —— 免费，不用信用卡，5 分钟搞定：
 *
 *   1. 打开 https://dash.deno.com  → 用 GitHub 或邮箱登录
 *   2. 点「New Playground」
 *   3. 把这个文件的全部内容粘进去，点 Save & Deploy
 *   4. 拿到一个 https://xxx.deno.dev 的地址，填到 App 的「我的 → 服务器」
 *   5. （可选）在 Playground 的 Settings → Environment Variables 里加
 *      RELAY_TOKEN = 你的口令，然后用同一个口令填 App 的「服务器口令」
 *
 * 接口和 ntfy.sh 的最小可用子集一致：
 *   POST /<topic>                发一条消息（body 就是密文）
 *   GET  /<topic>/sse            订阅（Server-Sent Events）
 *   GET  /<topic>/json?poll=1    拉历史（换行分隔 JSON）
 *   GET  /healthz                健康检查
 *
 * 注意：Deno Deploy 是无服务器平台，历史只存在当前实例的内存里。
 * 两个人用完全够（消息都是秒级转发），但别指望它当长期数据库。
 */

const VERSION = "1.1.0";
const KEEP_MS = 12 * 3600 * 1000;
const MAX_PER_TOPIC = 2000;
const TOKEN = Deno.env.get("RELAY_TOKEN") || "";

/** topic -> [{id,time,event,topic,message}] */
const rooms = new Map();
/** topic -> Set<{write,close}> */
const streams = new Map();

function rid() {
  const b = new Uint8Array(9);
  crypto.getRandomValues(b);
  return btoa(String.fromCharCode(...b)).replace(/[+/=]/g, "").slice(0, 12);
}
function authed(req, url) {
  if (!TOKEN) return true;
  const h = req.headers.get("authorization") || "";
  return h === "Bearer " + TOKEN || h === TOKEN || url.searchParams.get("auth") === TOKEN;
}
const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "*",
  "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
  "Cache-Control": "no-store",
};
function json(obj, code = 200) {
  return new Response(JSON.stringify(obj), {
    status: code,
    headers: { "Content-Type": "application/json; charset=utf-8", ...CORS },
  });
}

setInterval(() => {
  const cut = Date.now() - KEEP_MS;
  for (const [t, list] of rooms) {
    const keep = list.filter((m) => m.time * 1000 >= cut);
    if (keep.length) rooms.set(t, keep); else rooms.delete(t);
  }
  for (const set of streams.values()) for (const c of set) c.ping();
}, 60000);

Deno.serve(async (req) => {
  const url = new URL(req.url);
  const path = decodeURIComponent(url.pathname);

  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });

  if (path === "/healthz" || path === "/") {
    return json({ ok: true, service: "liangkeixin-relay", version: VERSION, runtime: "deno", rooms: rooms.size });
  }

  const m = path.match(/^\/([^/]+?)(\/(sse|json))?$/);
  if (!m) return json({ error: "not found" }, 404);
  const topic = m[1];
  const sub = m[3] || "";
  if (!/^[-_A-Za-z0-9]{1,64}$/.test(topic)) return json({ error: "bad topic" }, 400);

  /* ---- 发布 ---- */
  if (req.method === "POST") {
    if (!authed(req, url)) return json({ error: "unauthorized" }, 401);
    const body = (await req.text()).slice(0, 2 * 1024 * 1024);
    if (!body) return json({ error: "empty body" }, 400);
    const msg = { id: rid(), time: Math.floor(Date.now() / 1000), event: "message", topic, message: body };
    let list = rooms.get(topic);
    if (!list) { list = []; rooms.set(topic, list); }
    list.push(msg);
    if (list.length > MAX_PER_TOPIC) list.splice(0, list.length - MAX_PER_TOPIC);
    const subs = streams.get(topic);
    if (subs) for (const c of subs) c.write(msg);
    return json(msg);
  }

  if (req.method !== "GET") return json({ error: "method not allowed" }, 405);

  /* ---- 订阅 ---- */
  if (sub === "sse") {
    if (!authed(req, url)) return json({ error: "unauthorized" }, 401);
    let set = streams.get(topic);
    if (!set) { set = new Set(); streams.set(topic, set); }
    const enc = new TextEncoder();
    let ctl = null;
    const conn = {
      write: (msg) => { try { ctl && ctl.enqueue(enc.encode("data: " + JSON.stringify(msg) + "\n\n")); } catch (_) {} },
      ping: () => { try { ctl && ctl.enqueue(enc.encode(": ping\n\n")); } catch (_) {} },
    };
    const body = new ReadableStream({
      start(c) {
        ctl = c;
        set.add(conn);
        c.enqueue(enc.encode(": connected\n\n"));
      },
      cancel() { set.delete(conn); if (!set.size) streams.delete(topic); },
    });
    return new Response(body, {
      headers: {
        "Content-Type": "text/event-stream; charset=utf-8",
        "Cache-Control": "no-cache, no-transform",
        "X-Accel-Buffering": "no",
        ...CORS,
      },
    });
  }

  /* ---- 拉历史 ---- */
  if (!authed(req, url)) return json({ error: "unauthorized" }, 401);
  const since = url.searchParams.get("since") || "";
  let cut = 0;
  const hm = /^(\d+)([hmd])$/.exec(since);
  if (hm) cut = Date.now() - (+hm[1]) * ({ h: 3600000, m: 60000, d: 86400000 })[hm[2]];
  else if (/^\d+$/.test(since)) cut = +since * 1000;
  const list = (rooms.get(topic) || []).filter((x) => x.time * 1000 >= cut);
  return new Response(list.map((x) => JSON.stringify(x)).join("\n"), {
    headers: { "Content-Type": "application/x-ndjson; charset=utf-8", ...CORS },
  });
});
