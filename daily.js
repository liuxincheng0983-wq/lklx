/* ===========================================================
   心动日常 —— 恋爱日常模块（独立文件，避免 app.js 继续膨胀）
   -----------------------------------------------------------
   包含：恋爱日历 / 每日打卡365 / 甜言蜜语 / 心情日记 / 心动相册 /
        恋爱清单 / 冰箱贴 / 约会转盘 / 默契挑战 / 萌宠 / 健康助手 /
        情侣闹钟 / 轨迹回放 / 聊天备份 / 情侣装扮（自定义开屏）
   数据都存在本机 localStorage，改动通过暗号加密后发给对方，
   服务器只是转发密文，看不到内容。
   =========================================================== */
(function () {
  'use strict';

  var KEY = 'lklx.daily';
  var DEF = {
    since: '',                 // 恋爱纪念日 YYYY-MM-DD
    love: {},                  // 打卡 {'YYYY-MM-DD': {me:ts, peer:ts}}
    greet: [],                 // 甜言蜜语 [{t,from,kind,txt}]
    moods: [],                 // 心情日记 [{t,from,m,txt}]
    photos: [],                // 相册 [{id,t,from,data,cap}]
    list: [],                  // 恋爱清单 [{id,txt,done:{me,peer},rec:{data,place,t,from}}]
    notes: [],                 // 冰箱贴 [{id,t,from,txt,color}]
    quiz: [],                  // 默契挑战 [{id,q,ans,from,t}]
    quizPool: [],              // 本局配对中的题目
    pet: { name: '团子', lv: 1, exp: 0, hungry: 100, lastFeed: 0, lastPet: 0, ts: 0 },
    health: { on: false, last: '', cycle: 28, days: 5, logs: [] },
    alarms: [],                // [{id,time,label,days:[],owner}]
    theme: 'pink',
    splash: { on: false, txt: '', ms: 1500 }
  };
  var D = Object.assign({}, DEF, JSON.parse(localStorage.getItem(KEY) || 'null') || {});
  var H = null;               // host：由 app.js 注入
  var view = 'home';
  var recEdit = null;      // 正在补记录的清单条目 {id,data,place,t}
  var selectedPhoto = null;

  function save() { try { localStorage.setItem(KEY, JSON.stringify(D)); } catch (e) {} }
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function dayKey(t) {
    var d = new Date(t || Date.now());
    return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0');
  }
  function hhmm(t) {
    var d = new Date(t);
    return String(d.getHours()).padStart(2, '0') + ':' + String(d.getMinutes()).padStart(2, '0');
  }
  function ago(t) {
    var s = Math.floor((Date.now() - t) / 1000);
    if (s < 60) return '刚刚';
    if (s < 3600) return Math.floor(s / 60) + ' 分钟前';
    if (s < 86400) return Math.floor(s / 3600) + ' 小时前';
    return Math.floor(s / 86400) + ' 天前';
  }
  function rid() { return 'r' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6); }
  function send(op, item, extra) {
    if (!H) return;
    var o = { v: 1, k: 'd', id: H.myId(), op: op, item: item || null, t: Date.now() };
    if (extra) for (var k in extra) o[k] = extra[k];
    H.publish(o);
  }
  function toast(m, heart) { if (H) H.toast(m, heart); }

  /* ---------------- 恋爱天数 / 打卡 ---------------- */
  function loveDays() {
    if (!D.since) return 0;
    var a = new Date(D.since + 'T00:00:00'), b = new Date();
    return Math.floor((b - a) / 86400000) + 1;
  }
  function streak() {
    var n = 0, d = new Date();
    for (; ;) {
      var k = dayKey(d.getTime());
      var c = D.love[k];
      if (c && (c.me || c.peer)) { n++; d.setDate(d.getDate() - 1); } else break;
      if (n > 400) break;
    }
    return n;
  }
  function checkin() {
    var k = dayKey();
    var c = D.love[k] || (D.love[k] = {});
    if (c.me) { toast('今天已经说过啦 💕'); return; }
    c.me = Date.now();
    save();
    send('love', { date: k, ts: c.me });
    if (H) H.hearts && H.hearts(10);
    petGain(6);
    toast('打卡成功，第 ' + streak() + ' 天 💕', true);
    render();
  }
  function onLove(item) {
    var k = item && item.date; if (!k) return;
    var c = D.love[k] || (D.love[k] = {});
    c.peer = item.ts || Date.now();
    if (c.me && Math.abs(c.me - c.peer) < 300000) { petGain(4); }
    save();
    note('<b>TA 说了「我爱你」</b><br>今天的打卡集齐了 💕');
  }

  /* ---------------- 甜言蜜语 ---------------- */
  var WORDS = [
    '今天也很想你，比昨天多一点点。', '你在的地方，风都是甜的。', '想和你把日子过得很慢很慢。',
    '见到你之前，我先替你把快乐存好。', '你不用完美，你只要是你。', '想变成你手机里最多余的那格电，一直陪着你。',
    '今晚的月亮很好看，但不如你。', '所有的好运气，都想留给你一半。', '你回头的时候，我一定在。',
    '愿我们所有的争吵，最后都能变成更了解彼此。', '你是我平淡日子里的糖。', '想牵着你的手，把所有的路都走一遍。'
  ];
  function greet(kind) {
    var txt = kind === 'love' ? WORDS[Math.floor(Math.random() * WORDS.length)] : kind;
    var item = { t: Date.now(), from: H.myId(), kind: kind, txt: kind === 'love' ? txt : '' };
    D.greet.push(item); if (D.greet.length > 200) D.greet.shift();
    save();
    send('greet', item);
    if (kind === 'love') { H.publish({ v: 1, k: 'msg', id: H.myId(), n: (H.myName() || '我'), msg: '💌 ' + txt, t: Date.now() }); }
    else { H.publish({ v: 1, k: 'msg', id: H.myId(), n: (H.myName() || '我'), msg: kind + ' ☀️', t: Date.now() }); }
    toast(kind === 'love' ? '情话已送达' : kind + ' 已发送', true);
    petGain(3);
    render();
  }
  function onGreet(item) {
    D.greet.push(item); if (D.greet.length > 200) D.greet.shift(); save();
    note('💌 <b>TA 发来的' + (item.kind === 'love' ? '情话' : item.kind) + '</b><br>' + esc(item.txt || ''));
    render();
  }

  /* ---------------- 心情日记 ---------------- */
  var MOODS = [['😊', '开心'], ['🥰', '想你'], ['😐', '一般'], ['😮‍💨', '累了'], ['😢', '难过'], ['😤', '生气'], ['🤒', '不舒服']];
  function addMood(m, txt) {
    var item = { t: Date.now(), from: H.myId(), m: m, txt: txt || '' };
    D.moods.push(item); if (D.moods.length > 200) D.moods.shift(); save();
    send('mood', item);
    toast('心情已记录', true);
    render();
  }
  function onMood(item) {
    D.moods.push(item); if (D.moods.length > 200) D.moods.shift(); save();
    note('今天 TA 的心情是 ' + item.m + (item.txt ? '<br>' + esc(item.txt) : ''));
    render();
  }

  /* ---------------- 心动相册 ---------------- */
  function pickPhoto(cb) {
    var inp = document.createElement('input');
    inp.type = 'file'; inp.accept = 'image/*';
    inp.onchange = function () {
      var f = inp.files && inp.files[0]; if (!f) return;
      var fr = new FileReader();
      fr.onload = function () {
        var img = new Image();
        img.onload = function () {
          var max = 1100, w = img.width, h = img.height;
          if (w > max || h > max) { var r = Math.min(max / w, max / h); w = Math.round(w * r); h = Math.round(h * r); }
          var cv = document.createElement('canvas'); cv.width = w; cv.height = h;
          cv.getContext('2d').drawImage(img, 0, 0, w, h);
          cb(cv.toDataURL('image/jpeg', 0.72));
        };
        img.src = fr.result;
      };
      fr.readAsDataURL(f);
    };
    inp.click();
  }
  function addPhoto(data, cap) {
    var item = { id: rid(), t: Date.now(), from: H.myId(), data: data, cap: cap || '' };
    // 压缩后一般 100~250KB，公共通道也发得动；更大的就提醒一句
    var pub = H.relayPublic ? H.relayPublic() : true;
    if (pub && data.length > 400000) {
      toast('这张有点大（' + Math.round(data.length / 1024) + 'KB），会慢一些；填了自建服务器会快很多', true);
    }
    D.photos.unshift(item);
    if (D.photos.length > 60) D.photos.pop();      // 相册上限 60 张，避免把 localStorage 撑爆
    save();
    send('photo', item);
    petGain(5);
    toast('照片已放进相册（对方也会收到）', true);
    render();
  }
  function onPhoto(item) {
    D.photos.unshift(item);
    if (D.photos.length > 60) D.photos.pop();
    save();
    note('📸 <b>TA 发来一张照片</b>');
    render();
  }

  /* ---------------- 恋爱清单 ---------------- */
  var LIST_DEF = [
    '一起看一场日出', '一起看一场雪', '一起坐一次摩天轮', '一起做完一顿饭', '一起看同一部电影',
    '一起去一次游乐园', '一起唱一次KTV', '一起养一盆植物', '一起去海边踩水', '一起看一次烟花',
    '一起吃路边摊', '一起去爬山', '一起做一次蛋糕', '一起逛超市买菜', '一起拍一组情侣照',
    '一起在雨天共撑一把伞', '一起去图书馆安静待一下午', '一起坐一次绿皮火车', '一起看一次演唱会',
    '一起在深夜散步', '一起给对方写一封信', '一起过一次生日', '一起去一次动物园', '一起泡一次温泉',
    '一起放一次风筝', '一起拼一次拼图', '一起打扫房间', '一起看星星', '一起攒钱买一样东西',
    '一起去一次异地旅行'
  ];
  function ensureList() {
    if (D.list.length) return;
    D.list = LIST_DEF.map(function (t, i) { return { id: 'L' + i, txt: t, done: { me: false, peer: false } }; });
    save();
  }
  function toggleListItem(id) {
    var it = D.list.filter(function (x) { return x.id === id; })[0]; if (!it) return;
    it.done.me = !it.done.me;
    save();
    send('list', { id: id, me: it.done.me });
    if (it.done.me && it.done.peer) { note('🎉 你们完成了：<b>' + esc(it.txt) + '</b>'); petGain(10); }
    // 打勾之后直接问一句「要不要加照片和地点」——比藏在菜单里好找
    if (it.done.me && !it.rec) openRec(id);
    else { recEdit = null; render(); }
  }
  function onListItem(item) {
    var it = D.list.filter(function (x) { return x.id === item.id; })[0]; if (!it) return;
    it.done.peer = !!item.me;
    save();
    if (it.done.peer && it.done.me) note('🎉 你们完成了：<b>' + esc(it.txt) + '</b>');
    render();
  }

  /* ---------------- 冰箱贴 ---------------- */
  var NOTE_COLORS = ['#FFE38A', '#A8E6CF', '#FFC9DD', '#BFD8FF', '#E7D3FF'];
  function addNote(txt, color) {
    var item = { id: rid(), t: Date.now(), from: H.myId(), txt: txt, color: color || NOTE_COLORS[0] };
    D.notes.unshift(item);
    if (D.notes.length > 40) D.notes.pop();
    save();
    send('note', item);
    toast('贴上去啦', true);
    render();
  }
  function onNote(item) {
    D.notes.unshift(item);
    if (D.notes.length > 40) D.notes.pop();
    save();
    note('🧲 <b>冰箱贴</b><br>' + esc(item.txt));
    render();
  }

  /* ---------------- 约会转盘 ---------------- */
  var IDEAS = [
    '去江边散步，买杯奶茶', '找家没吃过的小馆子', '在家做一顿饭 + 一部电影',
    '去逛书店，各挑一本送给对方', '骑共享单车乱逛一小时', '去超市买食材做火锅',
    '找个公园坐着聊天', '去拍一组街拍', '去看一场电影，散场再走回家',
    '去夜市从头吃到尾', '找个地方看日落', '去泡书店 + 咖啡馆待一下午'
  ];
  function spin() {
    var i = Math.floor(Math.random() * IDEAS.length);
    var idea = IDEAS[i];
    var box = document.getElementById('spinBox');
    var n = 0;
    var tm = setInterval(function () {
      if (!box) { clearInterval(tm); return; }
      box.querySelector('.idea').textContent = IDEAS[n++ % IDEAS.length];
      if (n > 18) {
        clearInterval(tm);
        box.querySelector('.idea').textContent = idea;
        box.querySelector('.spinGo').disabled = false;
        box.dataset.idea = idea;
      }
    }, 70);
  }
  function sendIdea(idea) {
    H.publish({ v: 1, k: 'msg', id: H.myId(), n: (H.myName() || '我'), msg: '🎡 今天我们去做：' + idea, t: Date.now() });
    send('idea', { txt: idea });
    toast('已经发给她了', true);
  }

  /* ---------------- 默契挑战 ---------------- */
  var QS = [
    ['我最喜欢的颜色是？', ['粉色', '蓝色', '白色', '黑色']],
    ['我最想去的城市是？', ['成都', '重庆', '大理', '厦门']],
    ['我心情不好时最想要？', ['抱抱', '安静待着', '吃好吃的', '出去走走']],
    ['我最喜欢的季节？', ['春天', '夏天', '秋天', '冬天']],
    ['我早餐最爱吃？', ['豆浆油条', '粥', '面包牛奶', '不吃']],
    ['我最怕的东西？', ['蟑螂', '高', '黑', '打针']],
    ['我周末最想做什么？', ['宅家', '出去玩', '睡觉', '逛街']],
    ['我最喜欢的口味？', ['辣', '甜', '咸', '酸']]
  ];
  function newQuiz() {
    var pick = QS[Math.floor(Math.random() * QS.length)];
    var item = { id: rid(), q: pick[0], opts: pick[1], ans: null, ansPeer: null, from: H.myId(), t: Date.now() };
    D.quiz.unshift(item); if (D.quiz.length > 20) D.quiz.shift();
    save(); render();
  }
  function answerQuiz(id, ans) {
    var it = D.quiz.filter(function (x) { return x.id === id; })[0]; if (!it) return;
    if (it.from === H.myId()) { it.ans = ans; send('quiz', { id: id, ans: ans, side: 'me' }); }
    else { it.ansPeer = ans; send('quiz', { id: id, ans: ans, side: 'peer' }); }
    save(); render();
  }
  function onQuiz(item) {
    var it = D.quiz.filter(function (x) { return x.id === item.id; })[0]; if (!it) return;
    if (item.side === 'peer') it.ansPeer = item.ans; else it.ans = item.ans;
    save();
    if (it.ans != null && it.ansPeer != null) {
      note(it.ans === it.ansPeer ? '🎯 <b>默契 +1</b><br>' + esc(it.q) + '<br>你们都选了「' + esc(it.ans) + '」'
        : '🙈 这题没对上<br>' + esc(it.q) + '<br>你选「' + esc(it.ansPeer) + '」，她选「' + esc(it.ans) + '」');
    }
    render();
  }
  function onQuizNew(item) {
    D.quiz.unshift(item); if (D.quiz.length > 20) D.quiz.shift(); save();
    note('🎯 <b>TA 出了一道默契题</b><br>' + esc(item.q));
    render();
  }

  /* ---------------- 萌宠 ---------------- */
  function petGain(n) {
    D.pet.exp += n;
    while (D.pet.exp >= 100) { D.pet.exp -= 100; D.pet.lv++; }
    D.pet.ts = Date.now();
    save();
    syncPet();
  }
  function syncPet() { send('pet', D.pet); }
  function feed() {
    if (Date.now() - D.pet.lastFeed < 30 * 60 * 1000) { toast('它刚吃过，过会儿再喂 🐱'); return; }
    D.pet.lastFeed = Date.now();
    D.pet.hungry = Math.min(100, D.pet.hungry + 30);
    D.pet.ts = Date.now();
    petGain(8); save(); render();
    toast('喂饱啦，亲密度 +8', true);
  }
  function patPet() {
    if (Date.now() - D.pet.lastPet < 60 * 1000) return;
    D.pet.lastPet = Date.now(); petGain(2); save(); render();
  }
  function onPet(item) {
    if (item && item.ts > (D.pet.ts || 0)) { D.pet = item; save(); render(); }
  }
  function petTick() {
    // 每小时掉一点饱食度
    var stage = Math.floor(Date.now() / 3600000);
    if (D.pet.hungryStage !== stage) {
      D.pet.hungryStage = stage;
      D.pet.hungry = Math.max(0, (D.pet.hungry || 100) - 2);
      save();
    }
  }

  /* ---------------- 健康助手 ---------------- */
  function healthNext() {
    if (!D.health.last) return null;
    var d = new Date(D.health.last + 'T00:00:00');
    d.setDate(d.getDate() + (D.health.cycle || 28));
    return d;
  }
  function addPeriod(dateStr) {
    D.health.last = dateStr;
    D.health.logs.unshift({ d: dateStr, t: Date.now() });
    if (D.health.logs.length > 24) D.health.logs.pop();
    save(); render();
    toast('已记录', true);
    if (D.health.share) send('health', { last: dateStr, cycle: D.health.cycle, days: D.health.days });
  }
  function onHealth(item) {
    D.health.last = item.last; D.health.cycle = item.cycle || 28; D.health.days = item.days || 5;
    save();
    note('🩸 TA 更新了健康记录（<b>仅供关心，不作医学建议</b>）');
    render();
  }

  /* ---------------- 情侣闹钟 ---------------- */
  function addAlarm(time, label, days) {
    var a = { id: rid(), time: time, label: label, days: days || [], owner: H.myId(), last: '' };
    D.alarms.push(a); save();
    send('alarm', a);
    toast('闹钟已加好，两边一起响 🔔', true);
    render();
  }
  function onAlarm(a) {
    if (D.alarms.filter(function (x) { return x.id === a.id; }).length) return;
    D.alarms.push(a); save();
    note('⏰ <b>TA 加了个闹钟</b><br>' + esc(a.time + ' ' + (a.label || '')));
    render();
  }
  function alarmTick() {
    var now = new Date();
    var hm = String(now.getHours()).padStart(2, '0') + ':' + String(now.getMinutes()).padStart(2, '0');
    var key = dayKey() + ' ' + hm;
    D.alarms.forEach(function (a) {
      if (a.time !== hm || a.last === key) return;
      a.last = key; save();
      var who = a.owner === H.myId() ? '我们' : 'TA';
      if (H.notify) H.notify('⏰ ' + (a.label || '闹钟'), hm + ' · ' + who + '设的闹钟响啦');
      note('⏰ <b>' + esc(a.label || '闹钟') + '</b> ' + hm);
    });
  }

  /* ---------------- 轨迹回放 ---------------- */
  var playTimer = null;
  function playTrail() {
    var pts = H.trail() || [];
    if (pts.length < 2) { toast('还没有足够的足迹'); return; }
    if (playTimer) { clearInterval(playTimer); playTimer = null; }
    var i = 0;
    var sl = document.getElementById('playSlider');
    playTimer = setInterval(function () {
      i += Math.max(1, Math.round(pts.length / 60));
      if (i >= pts.length) { i = pts.length - 1; clearInterval(playTimer); playTimer = null; }
      if (sl) sl.value = String(Math.round(i / (pts.length - 1) * 100));
      H.showAt(pts[i].lat, pts[i].lng);
    }, 90);
  }
  function seekTrail(pct) {
    var pts = H.trail() || []; if (!pts.length) return;
    var i = Math.min(pts.length - 1, Math.round(pct / 100 * (pts.length - 1)));
    if (playTimer) { clearInterval(playTimer); playTimer = null; }
    H.showAt(pts[i].lat, pts[i].lng);
  }

  /* ---------------- 聊天备份 / 装扮 ---------------- */
  function backupChat() {
    var data = H.exportChat();
    var txt = JSON.stringify(data);
    try {
      var blob = new Blob([txt], { type: 'application/json' });
      var a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = '两颗心-聊天备份-' + dayKey() + '.json';
      a.click();
      toast('备份文件已导出', true);
    } catch (e) {
      try { navigator.clipboard.writeText(txt); toast('备份内容已复制到剪贴板', true); } catch (e2) { toast('导出失败'); }
    }
  }
  function restoreChat() {
    var txt = prompt('把备份里的 JSON 粘进来：');
    if (!txt) return;
    try {
      var d = JSON.parse(txt);
      H.importChat(d);
      toast('聊天记录已恢复', true);
    } catch (e) { toast('这份备份看不懂'); }
  }
  var THEMES = {
    pink:   { n: '小猫粉', a: '#FF6B9D', b: '#F24E86' },
    cream:  { n: '奶油黄', a: '#FFC93D', b: '#F2994A' },
    mint:   { n: '薄荷绿', a: '#7FD8C4', b: '#3FBF9E' },
    sky:    { n: '天空蓝', a: '#7FC4FF', b: '#3F8FE0' },
    night:  { n: '夜色紫', a: '#B18CFF', b: '#7A4FD6' }
  };
  function setTheme(k) {
    D.theme = k; save();
    if (H.setTheme) H.setTheme(k, THEMES[k]);
    render();
    toast('主题换成「' + THEMES[k].n + '」', true);
  }
  function splashShow() {
    if (!D.splash.on || !D.splash.txt) return;
    var el = document.createElement('div');
    el.id = 'spx';
    el.style.cssText = 'position:fixed;inset:0;z-index:2147483646;display:grid;place-items:center;'
      + 'background:linear-gradient(160deg,#FFE9F2,#FFD9E7);color:#D63672;font-size:22px;font-weight:800;'
      + 'text-align:center;padding:30px;white-space:pre-wrap';
    el.textContent = D.splash.txt;
    document.body.appendChild(el);
    setTimeout(function () { el.remove(); }, D.splash.ms || 1500);
  }

  /* ---------------- 收到对方消息 ---------------- */
  function onMsg(o) {
    switch (o.op) {
      case 'love': onLove(o.item); break;
      case 'greet': onGreet(o.item); break;
      case 'mood': onMood(o.item); break;
      case 'photo': onPhoto(o.item); break;
      case 'list': onListItem(o.item); break;
      case 'listRec': onListRec(o.item); break;
      case 'note': onNote(o.item); break;
      case 'quiz': onQuiz(o.item); break;
      case 'quizNew': onQuizNew(o.item); break;
      case 'pet': onPet(o.item); break;
      case 'health': onHealth(o.item); break;
      case 'alarm': onAlarm(o.item); break;
      case 'idea': break;
      case 'since': D.since = (o.item && o.item.since) || D.since; save(); break;
      default: break;
    }
    if (view === 'home') render();
  }
  function note(html) { if (H && H.note) H.note('心动日常', html); }

  /* ---------------- 首页（打开 App 第一眼） ---------------- */
  function renderHome() {
    var hero = document.getElementById('homeHero');
    var grid = document.getElementById('homeGrid');
    if (!hero || !grid) return;
    var today = D.love[dayKey()] || {};
    var meName = H.myName ? H.myName() : '我';
    var peName = H.peerName ? H.peerName() : 'TA';
    var pe = H.peerOn ? H.peerOn() : false;

    hero.innerHTML =
      '<div class="dhero">'
      + '<div class="dpair">'
      + '<div class="pav2">' + H.myAvatar() + '</div>'
      + '<div class="dheart">' + H.heart('#FFFFFF', 24) + '</div>'
      + '<div class="pav2">' + H.peerAvatar() + '</div>'
      + '<div class="dnames">' + esc(meName) + ' & ' + esc(peName)
      + (pe ? ' · 在线' : '') + '</div>'
      + '</div>'
      + '<div class="dh1">' + (D.since ? '我们已经在一起 <b>' + loveDays() + '</b> 天' : '写下你们在一起的那天') + '</div>'
      + '<div class="dh2">连续打卡 ' + streak() + ' 天'
      + (today.peer ? ' · TA 今天也说过了 💕' : (today.me ? ' · 等 TA 回你一句' : '')) + '</div>'
      + loveStrip()
      + '<button class="btnLoveHero' + (today.me ? ' done' : '') + '" id="btnLove">'
      + (today.me ? '✓ 今天已经说过「我爱你」' : '对她说「我爱你」💕') + '</button>'
      + (D.since ? '' : '<button class="btn sm ghost" id="btnSince" style="margin-top:9px">设置恋爱纪念日 / 见面日</button>')
      + '</div>';

    var extra = (H.extraCards && H.extraCards()) || [];
    var cards = extra.concat([
      ['💌', '甜言蜜语', D.greet.length ? D.greet.length + ' 条悄悄话' : '早安午安晚安', 'greet', D.greet.length || ''],
      ['📔', '心情日记', D.moods.length ? '最新 ' + ago(D.moods[D.moods.length - 1].t) : '记录今天的心情', 'mood', D.moods.length || ''],
      ['📸', '心动相册', D.photos.length ? D.photos.length + ' 张甜蜜瞬间' : '共享甜蜜瞬间', 'photo', D.photos.length || ''],
      ['✅', '恋爱清单', '一起完成 ' + listProgress() + ' 件小事', 'list', ''],
      ['🧲', '冰箱贴', D.notes.length ? D.notes.length + ' 张留言' : '给 TA 留句话', 'note', D.notes.length || ''],
      ['🎡', '约会转盘', '今天去哪吃玩', 'idea', ''],
      ['🎯', '默契挑战', D.quiz.length ? '最近 ' + D.quiz.length + ' 题' : '看看你懂不懂我', 'quiz', D.quiz.length || ''],
      ['🐱', D.pet.name, 'Lv.' + D.pet.lv + ' · 亲密度 ' + (D.pet.exp | 0) + '%', 'pet', ''],
      ['🩸', '健康助手', D.health.on ? '记录中' : '周期记录与提醒', 'health', ''],
      ['⏰', '情侣闹钟', D.alarms.length ? D.alarms.length + ' 个闹钟' : '早安晚安一起响', 'alarm', D.alarms.length || ''],
      ['🛰', '轨迹回放', '把走过的路走一遍', 'replay', ''],
      ['🎨', '情侣装扮', THEMES[D.theme || 'pink'].n, 'skin', ''],
      ['💾', '聊天备份', '导出 / 恢复记录', 'backup', '']
    ]);
    grid.innerHTML = cards.map(function (c, i) {
      return '<button class="hcard g' + ((i % 8) + 1) + '" data-go="' + c[3] + '">'
        + (c[4] ? '<span class="hbadge">' + c[4] + '</span>' : '')
        + '<span class="he">' + c[0] + '</span><b>' + c[1] + '</b><small>' + c[2] + '</small></button>';
    }).join('');

    var b1 = document.getElementById('btnLove'); if (b1) b1.onclick = checkin;
    var b2 = document.getElementById('btnSince'); if (b2) b2.onclick = askSince;
    grid.querySelectorAll('[data-go]').forEach(function (b) {
      b.onclick = function () {
        var k = b.dataset.go;
        if (H.action && H.action(k)) return;   // 地图/悄悄话/报备归 app.js 管
        open(k);
      };
    });
  }
  function askSince() {
    var v = prompt('恋爱纪念日（格式 2024-05-20）', D.since || dayKey());
    if (!v) return;
    D.since = v.trim(); save(); send('since', { since: D.since }); renderHome(); render();
  }

  /* ---------------- 界面 ---------------- */
  function card(emoji, title, sub, key, gi, badge) {
    return '<button class="dcard g' + ((gi % 8) + 1) + '" data-go="' + key + '">'
      + (badge ? '<span class="dbadge">' + badge + '</span>' : '')
      + '<span class="de">' + emoji + '</span>'
      + '<b>' + title + '</b><small>' + sub + '</small></button>';
  }
  function loveStrip() {
    var out = '', d = new Date();
    for (var i = 34; i >= 0; i--) {
      var x = new Date(d.getTime() - i * 86400000);
      var c = D.love[dayKey(x.getTime())] || {};
      var cls = c.me && c.peer ? 'both' : (c.me || c.peer ? 'half' : '');
      out += '<i class="' + cls + '" title="' + dayKey(x.getTime()) + '">' + (cls ? '❤' : '') + '</i>';
    }
    return '<div class="heartstrip" id="heartStrip">' + out + '</div>';
  }
  function render() {
    var el = document.getElementById('dailyBody');
    if (!el) return;
    var today = D.love[dayKey()] || {};
    var v = '';
    if (false) {
    } else if (view === 'greet') {
      v = '<div class="dsec"><h3>甜言蜜语</h3>'
        + '<div class="btngrid" style="margin-bottom:10px">'
        + '<button class="btn sm" data-greet="早安 ☀️">早安</button>'
        + '<button class="btn sm ghost" data-greet="午安 🌤">午安</button>'
        + '<button class="btn sm ghost" data-greet="晚安 🌙">晚安</button>'
        + '<button class="btn sm" data-greet="love">说句情话 💌</button>'
        + '</div>'
        + listOf(D.greet, function (g) {
            return '<div class="drow"><span class="dt">' + hhmm(g.t) + '</span>'
              + '<span class="dmain">' + (g.kind === 'love' ? '💌 ' + esc(g.txt) : esc(g.kind)) + '</span></div>';
          }, '还没有打招呼记录')
        + '</div>';
    } else if (view === 'mood') {
      v = '<div class="dsec"><h3>心情日记</h3>'
        + '<div class="moodrow">' + MOODS.map(function (m) { return '<button data-mood="' + m[0] + '">' + m[0] + '<small>' + m[1] + '</small></button>'; }).join('') + '</div>'
        + '<div class="field"><input id="moodTxt" placeholder="想说的话（可留空）" maxlength="60"></div>'
        + '<button class="btn sm" id="btnMoodSave">记下来</button>'
        + '<div class="dsep"></div>'
        + listOf(D.moods, function (m) {
            var mine = m.from === H.myId();
            return '<div class="drow"><span class="dt">' + (mine ? '我' : 'TA') + '</span>'
              + '<span class="dmain">' + m.m + ' ' + esc(m.txt) + '</span>'
              + '<span class="dt">' + ago(m.t) + '</span></div>';
          }, '还没有心情记录')
        + '</div>';
    } else if (view === 'photo') {
      v = '<div class="dsec"><h3>心动相册 <span class="dhint">最多 60 张，加密发送</span></h3>'
        + '<button class="btn sm" id="btnAddPhoto">＋ 添加照片</button>'
        + (D.photos.length ? '<div class="pgrid">' + D.photos.map(function (p) {
            return '<div class="pcell" data-photo="' + p.id + '"><img src="' + p.data + '"></div>';
          }).join('') + '</div>' : '<div class="empty">还没有照片</div>')
        + '</div>';
    } else if (view === 'list') {
      ensureList();
      v = '<div class="dsec"><h3>恋爱清单 <span class="dhint">' + listProgress() + '</span></h3>'
        + '<div class="note" style="margin:0 0 12px">做完一件就点一下，可以顺手加上<b>照片、地点和时间</b> —— 以后翻回来就是一本恋爱相册。</div>'
        + '<div class="lbar"><i style="width:' + Math.round(listPct()) + '%"></i></div>'
        + D.list.map(function (it) {
            var both = it.done.me && it.done.peer;
            var rec = it.rec || null;
            var recHtml = '';
            if (rec && (rec.data || rec.place || rec.t)) {
              recHtml = '<div class="rec">'
                + (rec.data ? '<img src="' + rec.data + '" data-recshot="' + it.id + '">' : '')
                + (rec.place ? '<span class="rtag">📍 ' + esc(rec.place) + '</span>' : '')
                + (rec.t ? '<span class="rtag">🕒 ' + dayKey(rec.t) + ' ' + hhmm(rec.t) + '</span>' : '')
                + '</div>';
            }
            var editor = (recEdit && recEdit.id === it.id) ? recForm(it) : '';
            return '<div class="lwrap"><div class="lrow' + (both ? ' done' : '') + '">'
              + '<button class="lchk' + (it.done.me ? ' on' : '') + '" data-li="' + it.id + '">'
              + (it.done.me ? '✓' : '') + '</button>'
              + '<span class="ltxt">' + esc(it.txt) + '</span>'
              + '<button class="lrec" data-rec="' + it.id + '" title="加照片/地点/时间">'
              + (rec ? '✎' : '＋') + '</button>'
              + '<span class="lwho">' + (it.done.peer ? 'TA✓' : '') + '</span></div>'
              + recHtml + editor + '</div>';
          }).join('')
        + '</div>';
    } else if (view === 'note') {
      v = '<div class="dsec"><h3>冰箱贴</h3>'
        + '<div class="field"><input id="noteTxt" placeholder="给 TA 留一句话" maxlength="40"></div>'
        + '<div class="notecolors">' + NOTE_COLORS.map(function (c) { return '<button data-nc="' + c + '" style="background:' + c + '"></button>'; }).join('') + '</div>'
        + '<button class="btn sm" id="btnAddNote" style="margin-top:10px">贴上</button>'
        + '<div class="stickies">' + D.notes.map(function (n) {
            var mine = n.from === H.myId();
            return '<div class="sticky" style="background:' + (n.color || NOTE_COLORS[0]) + '">'
              + '<b>' + (mine ? '我' : 'TA') + '</b><p>' + esc(n.txt) + '</p><small>' + ago(n.t) + '</small></div>';
          }).join('') + '</div>'
        + '</div>';
    } else if (view === 'idea') {
      v = '<div class="dsec"><h3>约会转盘</h3>'
        + '<div class="spinbox" id="spinBox"><div class="idea">点下面的按钮转一下 🎡</div>'
        + '<button class="btn spinGo" id="btnSpin" style="margin-top:12px">转一下</button>'
        + '<button class="btn sm ghost spinSend" id="btnSendIdea" style="margin-top:8px">就它了，发给 TA</button></div>'
        + '</div>';
    } else if (view === 'quiz') {
      v = '<div class="dsec"><h3>默契挑战</h3>'
        + '<button class="btn sm" id="btnNewQuiz" style="margin-bottom:10px">出一道新题</button>'
        + D.quiz.map(function (q) {
            var mine = q.from === H.myId();
            var myA = mine ? q.ans : q.ansPeer;
            var heA = mine ? q.ansPeer : q.ans;
            var same = myA && heA && myA === heA;
            return '<div class="qcard"><div class="qq">' + esc(q.q) + '</div>'
              + '<div class="qopts">' + (q.opts || []).map(function (o) {
                  return '<button data-q="' + q.id + '" data-a="' + esc(o) + '" class="' + (myA === o ? 'on' : '') + '">' + esc(o) + '</button>';
                }).join('') + '</div>'
              + (myA && heA ? '<div class="qr ' + (same ? 'ok' : '') + '">' + (same ? '🎯 默契一致！' : '🙈 没对上（TA 选「' + esc(heA) + '」）') + '</div>' : '')
              + '</div>';
          }).join('')
        + '</div>';
    } else if (view === 'pet') {
      petTick();
      var hung = D.pet.hungry == null ? 100 : D.pet.hungry;
      var face = hung < 30 ? '(=；ω；=)' : (hung < 60 ? '(=^･ω･^=)' : '(=^･ω･^=) ♪');
      v = '<div class="dsec"><h3>' + esc(D.pet.name) + '</h3>'
        + '<div class="petbox"><div class="petface" id="petFace">' + face + '</div>'
        + '<div class="petlv">Lv.' + D.pet.lv + ' · 亲密度 ' + (D.pet.exp | 0) + '%</div>'
        + '<div class="pbar"><i style="width:' + Math.max(2, D.pet.exp | 0) + '%"></i></div>'
        + '<div class="petlv">饱食度 ' + Math.round(hung) + '%</div>'
        + '<div class="btngrid" style="margin-top:10px">'
        + '<button class="btn sm" id="btnFeed">🐟 喂它</button>'
        + '<button class="btn sm ghost" id="btnPet">🤲 摸摸头</button></div>'
        + '<div class="field" style="margin-top:12px"><label>改个名字</label>'
        + '<input id="petName" value="' + esc(D.pet.name) + '" maxlength="8"></div>'
        + '<button class="btn sm ghost" id="btnPetName">保存名字</button>'
        + '<div class="note" style="margin-top:10px">你们两个人一起养：打卡、发照片、完成清单都能让它长大。</div>'
        + '</div></div>';
    } else if (view === 'health') {
      var nx = healthNext();
      v = '<div class="dsec"><h3>健康助手</h3>'
        + '<div class="note" style="margin:0 0 10px">只作记录和提醒，不构成任何医学建议。默认只存本机，打开「同步给 TA」对方才看得到。</div>'
        + '<div class="row"><div class="k">上次开始日期</div><div class="v">' + (D.health.last || '未记录') + '</div></div>'
        + '<div class="row"><div class="k">周期长度</div><div class="v">' + D.health.cycle + ' 天</div></div>'
        + '<div class="row"><div class="k">经期长度</div><div class="v">' + D.health.days + ' 天</div></div>'
        + (nx ? '<div class="row"><div class="k">预计下次</div><div class="v">' + dayKey(nx.getTime()) + '</div></div>'
              + '<div class="row"><div class="k">距离下次</div><div class="v">' + Math.max(0, Math.ceil((nx - Date.now()) / 86400000)) + ' 天</div></div>' : '')
        + '<div class="sw"><div class="k">同步给 TA<em>让 TA 知道该关心你了</em></div>'
        + '<input type="checkbox" id="swHealthShare" ' + (D.health.share ? 'checked' : '') + '></div>'
        + '<div class="field"><label>记录今天开始</label><input id="hDate" type="date" value="' + dayKey() + '"></div>'
        + '<button class="btn sm" id="btnHAdd">记录</button>'
        + '</div>';
    } else if (view === 'alarm') {
      v = '<div class="dsec"><h3>情侣闹钟</h3>'
        + '<div class="note" style="margin:0 0 10px">加一个闹钟，<b>两台手机会一起响</b> —— 异地也能一起起床。</div>'
        + '<div class="field"><label>时间</label><input id="alTime" type="time" value="07:00"></div>'
        + '<div class="field"><label>叫什么</label><input id="alLabel" placeholder="起床啦 / 记得吃饭" maxlength="12"></div>'
        + '<button class="btn sm" id="btnAlarmAdd">加闹钟</button>'
        + '<div class="dsep"></div>'
        + (D.alarms.length ? D.alarms.map(function (a) {
            return '<div class="drow"><span class="dt">' + a.time + '</span>'
              + '<span class="dmain">' + esc(a.label || '闹钟') + '</span>'
              + '<span class="dt">' + (a.owner === H.myId() ? '我' : 'TA') + '</span>'
              + '<button class="pdel" data-al="' + a.id + '">×</button></div>';
          }).join('') : '<div class="empty">还没有闹钟</div>')
        + '</div>';
    } else if (view === 'replay') {
      var pts = H.trail() || [];
      v = '<div class="dsec"><h3>轨迹回放 <span class="dhint">' + pts.length + ' 个点</span></h3>'
        + (pts.length > 1
          ? '<div class="rwrap"><button class="btn sm" id="btnPlay">▶ 播放今天走的路</button>'
            + '<input type="range" id="playSlider" min="0" max="100" value="0" style="width:100%;margin-top:14px">'
            + '<div class="note" style="margin-top:12px">拖动滑块可以看任意时间点她在哪；播放时地图上的头像会跟着走。</div></div>'
          : '<div class="empty">还没有足迹</div>')
        + '</div>';
    } else if (view === 'skin') {
      v = '<div class="dsec"><h3>情侣装扮</h3>'
        + '<div class="themegrid">' + Object.keys(THEMES).map(function (k) {
            var t = THEMES[k];
            return '<button class="thm' + (D.theme === k ? ' on' : '') + '" data-thm="' + k + '">'
              + '<span style="background:linear-gradient(140deg,' + t.a + ',' + t.b + ')"></span>' + t.n + '</button>';
          }).join('') + '</div>'
        + '<div class="dsep"></div>'
        + '<h4>自定义开屏（会员功能）</h4>'
        + '<div class="sw"><div class="k">开启开屏<em>每次打开 App 先看到这句话</em></div>'
        + '<input type="checkbox" id="swSplash" ' + (D.splash.on ? 'checked' : '') + '></div>'
        + '<div class="field"><label>开屏文字</label><input id="spTxt" maxlength="40" value="' + esc(D.splash.txt) + '" placeholder="今天也要好好想你"></div>'
        + '<div class="field"><label>显示时长（毫秒）</label><input id="spMs" type="number" min="600" max="5000" value="' + (D.splash.ms || 1500) + '"></div>'
        + '<button class="btn sm" id="btnSplashSave">保存开屏</button>'
        + '</div>';
    } else if (view === 'backup') {
      v = '<div class="dsec"><h3>聊天备份（会员功能）</h3>'
        + '<div class="note" style="margin:0 0 12px">导出成文件存起来，换手机或者清了缓存都能恢复。备份是明文 JSON，自己收好。</div>'
        + '<button class="btn sm" id="btnBackup">导出备份文件</button>'
        + '<button class="btn sm ghost" id="btnRestore" style="margin-top:8px">从备份恢复</button>'
        + '<div class="note" style="margin-top:12px">当前 <b>' + (H.chatCount() || 0) + '</b> 条消息 · '
        + D.photos.length + ' 张照片 · ' + D.moods.length + ' 条心情</div>'
        + '</div>';
    }
    el.innerHTML = v;
    bind();
  }
  function recForm(it) {
    var r = recEdit || {};
    return '<div class="recform">'
      + '<div style="font-size:12.5px;font-weight:800;color:#8A6070;margin-bottom:8px">'
      + '「' + esc(it.txt) + '」的完成记录</div>'
      + '<div style="display:flex;align-items:center;gap:10px">'
      + (r.data ? '<img class="thumb" src="' + r.data + '">' : '')
      + '<button class="btn sm ghost" id="recShot" style="flex:1">'
      + (r.data ? '换一张照片' : '📷 加张照片') + '</button></div>'
      + '<div class="field" style="margin-top:10px"><label>在哪里</label>'
      + '<input id="recPlace" value="' + esc(r.place || '') + '" placeholder="自动定位中…" maxlength="30"></div>'
      + '<div class="field"><label>什么时候</label>'
      + '<input id="recTime" type="datetime-local" value="' + toLocalInput(r.t || Date.now()) + '"></div>'
      + '<div class="row2"><button class="btn sm" id="recSave">保存记录</button>'
      + '<button class="btn sm ghost" id="recSkip">跳过</button></div>'
      + '</div>';
  }
  function toLocalInput(ts) {
    var d = new Date(ts - new Date().getTimezoneOffset() * 60000);
    return d.toISOString().slice(0, 16);
  }
  function openRec(id) {
    var it = D.list.filter(function (x) { return x.id === id; })[0];
    if (!it) return;
    recEdit = Object.assign({ id: id, data: null, place: '', t: Date.now() }, it.rec || {});
    selectedPhoto = null;
    render();
    if (H.place) {
      H.place(function (name) {
        if (recEdit && recEdit.id === id && name && !recEdit.place) {
          recEdit.place = name;
          var f = document.getElementById('recPlace');
          if (f) f.value = name;
        }
      });
    }
  }
  function saveRec() {
    if (!recEdit) return;
    var it = D.list.filter(function (x) { return x.id === recEdit.id; })[0];
    if (!it) return;
    var pl = document.getElementById('recPlace');
    var tm = document.getElementById('recTime');
    var rec = {
      data: recEdit.data || null,
      place: (pl ? pl.value : recEdit.place || '').trim(),
      t: tm && tm.value ? new Date(tm.value).getTime() : Date.now(),
      from: H.myId()
    };
    it.rec = rec;
    save();
    send('listRec', { id: it.id, rec: rec });
    recEdit = null;
    toast('记录保存好了 📸', true);
    render();
  }
  function onListRec(o) {
    var it = D.list.filter(function (x) { return x.id === o.id; })[0];
    if (!it || !o.rec) return;
    it.rec = o.rec;
    save();
    note('📸 <b>TA 完成了「' + esc(it.txt) + '」</b>'
      + (o.rec.place ? '<br>📍 ' + esc(o.rec.place) : ''));
    render();
  }

  function listOf(arr, fn, empty) {
    if (!arr || !arr.length) return '<div class="empty">' + empty + '</div>';
    return arr.slice().reverse().slice(0, 60).map(fn).join('');
  }
  function listProgress() { var n = 0; (D.list || []).forEach(function (i) { if (i.done.me && i.done.peer) n++; }); return n + '/' + ((D.list || []).length || LIST_DEF.length); }
  function listPct() { var t = (D.list || []).length || LIST_DEF.length; return t ? listProgress().split('/')[0] / t * 100 : 0; }

  function bind() {
    var el = document.getElementById('dailyBody');
    if (!el) return;
    el.querySelectorAll('[data-go]').forEach(function (b) {
      b.onclick = function () { view = b.dataset.go; if (view === 'list') ensureList(); render(); };
    });
    // 首页也可能被重新渲染，顺手把卡片事件接上
    var hg = document.getElementById('homeGrid');
    if (hg) hg.querySelectorAll('[data-go]').forEach(function (b) {
      b.onclick = function () {
        var k = b.dataset.go;
        if (H.action && H.action(k)) return;
        open(k);
      };
    });
    var back = document.getElementById('dailyBack');
    if (back) back.onclick = close;
    var b1 = document.getElementById('btnLove'); if (b1) b1.onclick = checkin;
    var b2 = document.getElementById('btnSince'); if (b2) b2.onclick = function () {
      var v = prompt('恋爱纪念日（格式 2024-05-20）', D.since || dayKey());
      if (!v) return;
      D.since = v.trim(); save(); send('since', { since: D.since }); render();
    };
    el.querySelectorAll('[data-greet]').forEach(function (b) { b.onclick = function () { greet(b.dataset.greet); }; });
    el.querySelectorAll('[data-mood]').forEach(function (b) { b.onclick = function () {
      var t = document.getElementById('moodTxt');
      addMood(b.dataset.mood, t ? t.value.trim() : '');
    }; });
    var b3 = document.getElementById('btnAddPhoto'); if (b3) b3.onclick = function () {
      pickPhoto(function (d) { var cap = prompt('写句说明？（可留空）', ''); addPhoto(d, cap || ''); });
    };
    el.querySelectorAll('[data-photo]').forEach(function (c) { c.onclick = function () {
      var p = D.photos.filter(function (x) { return x.id === c.dataset.photo; })[0]; if (!p) return;
      if (confirm('保存这张照片到手机？')) {
        var a = document.createElement('a'); a.href = p.data; a.download = '两颗心-' + dayKey(p.t) + '.jpg'; a.click();
      }
    }; });
    el.querySelectorAll('[data-li]').forEach(function (b) { b.onclick = function () { toggleListItem(b.dataset.li); }; });
    el.querySelectorAll('[data-rec]').forEach(function (b) { b.onclick = function () { openRec(b.dataset.rec); }; });
    el.querySelectorAll('[data-recshot]').forEach(function (img) {
      img.onclick = function () {
        var id = img.dataset.recshot;
        var it = D.list.filter(function (x) { return x.id === id; })[0];
        if (it && it.rec && it.rec.data) {
          var a = document.createElement('a'); a.href = it.rec.data;
          a.download = '两颗心-' + dayKey(it.rec.t) + '.jpg'; a.click();
        }
      };
    });
    var rs = document.getElementById('recShot');
    if (rs) rs.onclick = function () {
      pickPhoto(function (d) { if (recEdit) { recEdit.data = d; render(); } });
    };
    var rv = document.getElementById('recSave'); if (rv) rv.onclick = saveRec;
    var rk = document.getElementById('recSkip');
    if (rk) rk.onclick = function () { recEdit = null; render(); };
    el.querySelectorAll('[data-nc]').forEach(function (b) { b.onclick = function () {
      el.querySelectorAll('[data-nc]').forEach(function (x) { x.classList.remove('on'); });
      b.classList.add('on');
    }; });
    var b4 = document.getElementById('btnAddNote'); if (b4) b4.onclick = function () {
      var t = document.getElementById('noteTxt'); if (!t || !t.value.trim()) { toast('写点什么吧'); return; }
      var c = el.querySelector('[data-nc].on');
      addNote(t.value.trim(), c ? c.dataset.nc : NOTE_COLORS[0]);
    };
    var b5 = document.getElementById('btnSpin'); if (b5) b5.onclick = function () { b5.disabled = true; spin(); };
    var b6 = document.getElementById('btnSendIdea'); if (b6) b6.onclick = function () {
      var box = document.getElementById('spinBox');
      if (!box || !box.dataset.idea) { toast('先转一下'); return; }
      sendIdea(box.dataset.idea);
    };
    var b7 = document.getElementById('btnNewQuiz'); if (b7) b7.onclick = function () {
      var pick = QS[Math.floor(Math.random() * QS.length)];
      var item = { id: rid(), q: pick[0], opts: pick[1], ans: null, ansPeer: null, from: H.myId(), t: Date.now() };
      D.quiz.unshift(item); if (D.quiz.length > 20) D.quiz.shift();
      save();
      send('quizNew', { id: item.id, q: item.q, opts: item.opts, from: H.myId(), t: item.t });
      render();
    };
    el.querySelectorAll('[data-q]').forEach(function (b) { b.onclick = function () { answerQuiz(b.dataset.q, b.dataset.a); }; });
    var b8 = document.getElementById('btnFeed'); if (b8) b8.onclick = feed;
    var b9 = document.getElementById('btnPet'); if (b9) b9.onclick = function () { patPet(); toast('呼噜呼噜～', true); };
    var b10 = document.getElementById('btnPetName'); if (b10) b10.onclick = function () {
      var v = document.getElementById('petName'); if (!v) return;
      D.pet.name = v.value.trim() || '团子'; save(); syncPet(); render();
    };
    var b11 = document.getElementById('btnHAdd'); if (b11) b11.onclick = function () {
      var v = document.getElementById('hDate'); if (v) addPeriod(v.value);
    };
    var sw = document.getElementById('swHealthShare'); if (sw) sw.onchange = function () {
      D.health.share = sw.checked; save();
      if (sw.checked && D.health.last) send('health', { last: D.health.last, cycle: D.health.cycle, days: D.health.days });
    };
    var b12 = document.getElementById('btnAlarmAdd'); if (b12) b12.onclick = function () {
      var t = document.getElementById('alTime'), l = document.getElementById('alLabel');
      if (!t || !t.value) return;
      addAlarm(t.value, l ? l.value.trim() : '吵醒你');
    };
    el.querySelectorAll('[data-al]').forEach(function (b) { b.onclick = function () {
      D.alarms = D.alarms.filter(function (x) { return x.id !== b.dataset.al; }); save(); render();
    }; });
    var b13 = document.getElementById('btnPlay'); if (b13) b13.onclick = playTrail;
    var sl = document.getElementById('playSlider'); if (sl) sl.oninput = function () { seekTrail(+sl.value); };
    el.querySelectorAll('[data-thm]').forEach(function (b) { b.onclick = function () { setTheme(b.dataset.thm); }; });
    var sw2 = document.getElementById('swSplash'); if (sw2) sw2.onchange = function () { D.splash.on = sw2.checked; save(); };
    var b14 = document.getElementById('btnSplashSave'); if (b14) b14.onclick = function () {
      var t = document.getElementById('spTxt'), m = document.getElementById('spMs');
      D.splash.txt = t ? t.value : ''; D.splash.ms = Math.max(600, Math.min(5000, parseInt(m && m.value, 10) || 1500));
      D.splash.on = true; save();
      var swx = document.getElementById('swSplash'); if (swx) swx.checked = true;
      toast('开屏已保存，下次打开就能看到', true);
    };
    var b15 = document.getElementById('btnBackup'); if (b15) b15.onclick = backupChat;
    var b16 = document.getElementById('btnRestore'); if (b16) b16.onclick = restoreChat;
  }

  function open(key) {
    var el = document.getElementById('daily');
    if (!el) return;
    view = (key === 'home' || !key) ? 'greet' : key;
    if (key === 'list') ensureList();
    var t = document.getElementById('dailyTitle');
    if (t) t.textContent = TITLES[view] || '心动日常';
    el.hidden = false;
    render();
    var body = document.getElementById('dailyBody');
    if (body) body.scrollTop = 0;
  }
  function close() {
    var el = document.getElementById('daily');
    if (el) el.hidden = true;
    selectedPhoto = null; recEdit = null;
    renderHome();
  }
  var TITLES = {
    greet: '甜言蜜语', mood: '心情日记', photo: '心动相册', list: '恋爱清单',
    note: '冰箱贴', idea: '约会转盘', quiz: '默契挑战', pet: '萌宠',
    health: '健康助手', alarm: '情侣闹钟', replay: '轨迹回放', skin: '情侣装扮',
    backup: '聊天备份'
  };

  window.Daily = {
    init: function (host) {
      H = host;
      if (D.since && D.since.length === 10) { /* ok */ }
      ensureList();
      setTimeout(splashShow, 300);
    },
    open: open, close: close,
    home: renderHome,
    onPeer: function () { renderHome(); },
    onTick: function () {}, 
    onMsg: onMsg,
    importRaw: function (obj) {
      if (!obj || typeof obj !== 'object') return;
      Object.keys(DEF).forEach(function (k) { if (obj[k] !== undefined) D[k] = obj[k]; });
      save(); render();
    },
    render: render,
    tick: function () { alarmTick(); petTick(); },
    theme: function () { return THEMES[D.theme || 'pink']; },
    raw: function () { return D; },
    onRaw: function (o) { H = Object.assign({}, H, o); }
  };
})();
