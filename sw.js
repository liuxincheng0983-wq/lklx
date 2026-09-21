/* 两颗心 · 离线兜底 Service Worker
   目标：第一次成功打开后，应用外壳永久常驻本机。
   之后即便 GitHub Pages 打不开，页面照样启动。 */
var CACHE = 'lklx-v19';
var SHELL = [
  './',
  'index.html',
  'daily.js?v=19',
  'app.js?v=19',
  'kitty.js?v=19',
  'style.css?v=19',
  'manifest.json',
  'icon-192.png',
  'icon-180.png'
];

self.addEventListener('install', function (e) {
  e.waitUntil(
    caches.open(CACHE).then(function (c) {
      // 逐个装，单个失败不影响其余
      return Promise.all(SHELL.map(function (u) {
        return c.add(new Request(u, { cache: 'reload' })).catch(function () {});
      }));
    }).then(function () { return self.skipWaiting(); })
  );
});

self.addEventListener('activate', function (e) {
  e.waitUntil(
    caches.keys().then(function (ks) {
      return Promise.all(ks.map(function (k) {
        return k === CACHE ? null : caches.delete(k);
      }));
    }).then(function () { return self.clients.claim(); })
  );
});

function isTile(u) { return u.indexOf('autonavi.com') >= 0 || u.indexOf('vdata.amap.com') >= 0
         || u.indexOf('webapi.amap.com') >= 0 || u.indexOf('amappluss.alicdn.com') >= 0; }
function isRelay(u) { return u.indexOf('ntfy.sh') >= 0; }

self.addEventListener('fetch', function (e) {
  var req = e.request;
  if (req.method !== 'GET') return;

  var url = req.url;

  // 中继与 SSE：绝不缓存，永远走网络（否则收不到实时位置）
  if (isRelay(url)) return;

  // 高德瓦片：缓存优先 + 后台更新，限制数量
  if (isTile(url)) {
    e.respondWith(
      caches.open(CACHE + '-tiles').then(function (c) {
        return c.match(req).then(function (hit) {
          var net = fetch(req).then(function (res) {
            if (res && res.ok) {
              c.put(req, res.clone());
              c.keys().then(function (ks) {
                if (ks.length > 400) c.delete(ks[0]);
              });
            }
            return res;
          }).catch(function () { return hit; });
          return hit || net;
        });
      })
    );
    return;
  }

  // 非同源（其他）：直接放行
  if (url.indexOf(self.location.origin) !== 0) return;

  // 页面导航：网络优先，失败回落缓存
  if (req.mode === 'navigate') {
    e.respondWith(
      fetch(req).then(function (res) {
        var cp = res.clone();
        caches.open(CACHE).then(function (c) { c.put('index.html', cp); });
        return res;
      }).catch(function () {
        return caches.match('index.html').then(function (hit) {
          return hit || caches.match('./');
        });
      })
    );
    return;
  }

  // 同源静态资源：缓存优先 + 后台静默更新
  e.respondWith(
    caches.match(req).then(function (hit) {
      var net = fetch(req).then(function (res) {
        if (res && res.ok) {
          caches.open(CACHE).then(function (c) { c.put(req, res.clone()); });
        }
        return res;
      }).catch(function () { return hit; });
      return hit || net;
    })
  );
});
