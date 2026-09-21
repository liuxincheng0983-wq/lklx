# 两颗心 · 自建中转服务器

公共 ntfy.sh 免费版**每天只有 240 条**消息额度，够看位置，但一旦聊天、发照片、同步心动日常数据，很快就烧完，之后位置会静默停更（而且不报错）。

自己架一个就再没有这个限制。

---

## 一、为什么要自建

| | 公共 ntfy.sh | 自建 |
|---|---|---|
| 每天条数 | **240 条**（用完静默停更） | 不限 |
| 位置更新 | 被迫越放越慢（最低 30 分钟一次） | 按你设的频率，最快 4 秒 |
| 报文经过谁 | ntfy.sh 的服务器 | **只有你自己的机器** |
| 照片 / 心跳 | 抢额度 | 随便发 |
| 费用 | 免费 | 一台最便宜的 VPS（约 ¥10/月）或 Deno Deploy（免费） |

加密方式不变：位置和消息还是在手机上加密后才发出去，**服务器看到的只是一串密文**。

---

## 二、装（两条路，挑一条）

### 路线 A：有 VPS —— 一行命令

阿里云 / 腾讯云 / 搬瓦工 / 甲骨文免费机都行，Ubuntu 或 Debian。

SSH 上去，粘这一行：

```bash
curl -fsSL https://liuxincheng0983-wq.github.io/lklx/relay/install.sh | sudo bash
```

脚本会自己做完这些事：

- 装 Node（没装的话）
- 把服务装成开机自启（systemd）
- 自动生成一个口令
- 放行系统防火墙
- 自检并打印出**服务器地址 + 口令**

跑完你会看到：

```
────────────────────────────────────────────
  装好了 🎉  以后一天几万条也没人管你

  服务器地址（填到 App「我的 → 服务器」里）：
      http://123.45.67.89:8890

  口令（同一个地方，填「服务器口令」）：
      kQ7xN2mPvB3sT8wZ1cR4dY6h
────────────────────────────────────────────
```

> ⚠️ **最容易漏的一步**：云服务商的**安全组**也要放行 8890 端口。
> 只开系统防火墙是不够的 —— 阿里云、腾讯云默认安全组是关着的，
> 这是 90% 的人卡住的地方。
>
> 想用域名 + HTTPS：
> ```bash
> DOMAIN=relay.你的域名.com curl -fsSL … | sudo bash
> ```
> （域名要先解析到这台机器）

### 路线 B：没有 VPS —— Deno Deploy，免费

1. 打开 <https://dash.deno.com>，用 GitHub 或邮箱登录
2. 点 **New Playground**
3. 把 [`deno.js`](./deno.js) 的内容整份粘进去，点 **Save & Deploy**
4. 拿到一个 `https://xxxx.deno.dev` 地址
5. （可选）Playground → Settings → Environment Variables 加一个
   `RELAY_TOKEN = 随便一串口令`

把 `https://xxxx.deno.dev` 填到 App 里就行。

> Deno Deploy 免费、不用信用卡。缺点是历史只存在内存里
> —— 两个人用完全够，消息都是秒级转发。

---

## 三、接到 App 上

打开 App → **我的 → 服务器**：

| 填什么 | 填成 |
|---|---|
| 中转服务器地址 | `http://123.45.67.89:8890` 或 `https://xxxx.deno.dev` |
| 服务器口令 | 脚本打印的那一串 |

点 **测试连接** —— 出现「服务器在线 ✓ 123 ms · 已解除每日 240 条限制」就通了。
再点 **保存并重连**。

之后 App 里会显示「自建服务器 · 不限条数」，位置更新频率也会按你设的值走。

> 对方（她）也要填**一模一样的地址和口令**，否则你们在两条不同的路上说话。

---

## 四、跑起来之后

```bash
systemctl status  liangkeixin-relay     # 看状态
systemctl restart liangkeixin-relay     # 重启
journalctl -u liangkeixin-relay -f      # 实时看日志
journalctl -u liangkeixin-relay -n 100  # 看最近 100 行
```

**数据存在哪？** 只在内存里，保留 12 小时，进程重启就清空。
位置是实时用的，历史清掉无所谓 —— 你们的历史轨迹存在自己手机上。

**要备份吗？** 不用。没有数据库、没有用户表、没有日志文件。
两个人用，内存占用几十 KB，一年不重启也没事。

---

## 五、安全

- 密文原样转发：加解密在手机上做，密钥是你们的暗号，服务器读不懂
- 设了口令的话，发布和订阅都要带 `Authorization: Bearer <口令>`
- 单 IP 每分钟 600 次请求限速，防扫描
- systemd 里开了 `ProtectSystem=strict` / `NoNewPrivileges` 等，权限收到最小

---

## 六、环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `PORT` | `8890` | 监听端口 |
| `HOST` | `0.0.0.0` | 监听地址 |
| `RELAY_TOKEN` | 空 | 口令；留空则不校验（**公网一定要设**） |
| `KEEP_MS` | 12 小时 | 消息保留时长 |
| `MAX_PER_TOPIC` | `2000` | 单个房间最多缓存多少条 |
| `RATE_PER_MIN` | `600` | 单 IP 每分钟请求上限 |

---

## 七、文件说明

| 文件 | 干什么的 |
|---|---|
| `server.js` | **主程序**。Node 单文件，零依赖，`node server.js` 就能跑 |
| `install.sh` | VPS 一键安装脚本（上面路线 A 用的） |
| `deno.js` | Deno Deploy 版，粘到网页上就行（路线 B） |
| `liangkeixin-relay.service` | systemd 单元（install.sh 会自动生成一份带口令的） |
| `Caddyfile` | 用域名 + HTTPS 时的 Caddy 配置 |
| `nginx.conf.example` | 用 nginx 反代时的示例（注意 `proxy_buffering off`） |

手动跑（不想装成服务）：

```bash
RELAY_TOKEN=你的口令 PORT=8890 node server.js
```

---

## 八、接口

和 ntfy.sh 的最小可用子集一致，所以 App 和网页端一行都不用改：

```
POST /<topic>                 发一条消息（body 就是密文）
GET  /<topic>/sse             订阅（SSE 长连接）
GET  /<topic>/json?poll=1     拉历史（换行分隔的 JSON，支持 since=6h / since=3600）
GET  /healthz                 健康检查
```

自检：

```bash
curl http://127.0.0.1:8890/healthz
curl -X POST -d 'hello' http://127.0.0.1:8890/test
curl 'http://127.0.0.1:8890/test/json?poll=1&since=60s'
```
