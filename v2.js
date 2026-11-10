/* 新版界面（v2）：顶部搜索 + 左侧分组导航 + 紧凑账号列表。
   与旧版（app.js）共用同一份本地数据：simple2fa.board / simple2fa.groups，
   两边随时切换，数据不丢。新版额外给账号加了可选字段 fav（常用）和 used（最近复制时间），旧版会原样保留。 */
(function () {
  'use strict';
  const root = document.getElementById('v2');
  if (!root) return;

  const K_BOARD = 'simple2fa.board';
  const K_GROUPS = 'simple2fa.groups';
  const K_UI = 'simple2fa.ui';
  const K_PREFS = 'simple2fa.v2prefs';
  const PERIOD = 30;
  const K_ENVS = 'simple2fa.envs';
  // 名称里带这些词的，自动当成测试环境（只是默认值，可以手动改）
  const looksTest = (t) => /测试|沙盒|(^|[^a-z])(test|testing|sandbox)([^a-z]|$)/i.test(t || '');
  const RING = 97.39; // 2π × 15.5

  /* ---------- TOTP ---------- */
  const A32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  function b32decode(s) {
    s = (s || '').replace(/=+$/, '').replace(/\s/g, '').toUpperCase();
    if (!s || /[^A-Z2-7]/.test(s)) return null;
    let bits = 0, val = 0; const out = [];
    for (const ch of s) {
      val = (val << 5) | A32.indexOf(ch); bits += 5;
      if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; }
    }
    return out.length ? new Uint8Array(out) : null;
  }
  const keyCache = new Map();
  async function hotp(secret, counter) {
    let key = keyCache.get(secret);
    if (!key) {
      const raw = b32decode(secret);
      if (!raw) throw new Error('invalid secret');
      key = crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
      keyCache.set(secret, key);
    }
    const buf = new ArrayBuffer(8);
    const dv = new DataView(buf);
    dv.setUint32(0, Math.floor(counter / 0x100000000));
    dv.setUint32(4, counter >>> 0);
    const sig = new Uint8Array(await crypto.subtle.sign('HMAC', await key, buf));
    const off = sig[sig.length - 1] & 0x0f;
    const bin = ((sig[off] & 0x7f) << 24) | (sig[off + 1] << 16) | (sig[off + 2] << 8) | sig[off + 3];
    return String(bin % 1000000).padStart(6, '0');
  }

  function parseSecretInput(raw) {
    raw = (raw || '').trim();
    if (!raw) return null;
    let secret = '', label = '';
    if (/^otpauth:\/\//i.test(raw)) {
      try {
        const u = new URL(raw);
        secret = (u.searchParams.get('secret') || '').trim();
        const path = decodeURIComponent(u.pathname.replace(/^\/+/, ''));
        label = path.includes(':') ? path.split(':').slice(1).join(':').trim() : path;
      } catch (e) { return null; }
    } else if (raw.includes('secret=')) {
      const q = raw.includes('#') ? raw.slice(raw.indexOf('#') + 1) : raw.replace(/^\?/, '');
      const sp = new URLSearchParams(q);
      secret = (sp.get('secret') || '').trim();
      label = sp.get('label') || '';
    } else {
      secret = raw.replace(/\s/g, '');
    }
    if (!b32decode(secret)) return null;
    return { secret: secret.toUpperCase().replace(/\s/g, ''), label: label || '' };
  }
  function otpauthUrl(acc) {
    const sp = new URLSearchParams();
    sp.set('secret', acc.secret);
    sp.set('issuer', '2FA');
    return 'otpauth://totp/' + encodeURIComponent(acc.label || 'account') + '?' + sp.toString();
  }
  function bookmarkUrl(acc) {
    const sp = new URLSearchParams();
    sp.set('secret', acc.secret);
    if (acc.label) sp.set('label', acc.label);
    return location.origin + location.pathname + '#' + sp.toString();
  }
  function makeQrDataUrl(text) {
    if (typeof qrcode === 'undefined') return null;
    try { const qr = qrcode(0, 'M'); qr.addData(text); qr.make(); return qr.createDataURL(5, 2); }
    catch (e) { return null; }
  }
  function copyText(t) {
    if (navigator.clipboard && navigator.clipboard.writeText) return navigator.clipboard.writeText(t);
    const ta = document.createElement('textarea');
    ta.value = t; document.body.appendChild(ta); ta.select();
    const ok = document.execCommand('copy'); ta.remove();
    return ok ? Promise.resolve() : Promise.reject(new Error('copy failed'));
  }
  const fmt = (c) => c.slice(0, 3) + ' ' + c.slice(3);

  /* ---------- 数据（与旧版共用） ---------- */
  function readJSON(k, fb) {
    try { const v = JSON.parse(localStorage.getItem(k)); return v == null ? fb : v; } catch (_) { return fb; }
  }
  function writeJSON(k, v) {
    try { localStorage.setItem(k, JSON.stringify(v)); } catch (_) { toast('保存失败：浏览器存储不可用', true); }
  }
  let accounts = [], groups = [];
  function loadData() {
    accounts = readJSON(K_BOARD, []);
    if (!Array.isArray(accounts)) accounts = [];
    accounts = accounts.filter((a) => a && typeof a.secret === 'string');
    groups = readJSON(K_GROUPS, []);
    if (!Array.isArray(groups)) groups = [];
    groups = groups.filter((g) => g && typeof g.id === 'string' && typeof g.name === 'string');
    // 与旧版一致：一次性初始化默认分组，之后尊重用户的增删
    if (localStorage.getItem('simple2fa.defaultGroupsV1') !== '1') {
      for (const name of ['ejhcard', 'xf', 'jt']) {
        if (!groups.some((g) => g.name.toLowerCase() === name)) groups.push({ id: 'default-' + name, name });
      }
      writeJSON(K_GROUPS, groups);
      try { localStorage.setItem('simple2fa.defaultGroupsV1', '1'); } catch (_) {}
    }
  }
  loadData();
  // 第一次升级到带「环境」的版本：名称里带「测试 / test」的账号自动标成测试，其余不动
  if (localStorage.getItem('simple2fa.envDetectV1') !== '1') {
    let n = 0;
    for (const a of accounts) if (!a.env && looksTest(a.label)) { a.env = 'test'; n++; }
    if (n) writeJSON(K_BOARD, accounts);
    try { localStorage.setItem('simple2fa.envDetectV1', '1'); } catch (_) {}
  }
  // 环境：每个分组各有一份，可自己新建 / 改名 / 删除；没改过的分组默认有「正式」「测试」
  const defaultEnvs = () => [{ id: 'prod', name: '正式' }, { id: 'test', name: '测试' }];
  const okEnv = (x) => x && typeof x.id === 'string' && typeof x.name === 'string';
  let envsBy = {};       // { 分组id: [{id,name}] }，'' 是未分组；没有这一项就用默认
  function loadEnvs() {
    const e = readJSON(K_ENVS, null);
    envsBy = {};
    if (Array.isArray(e)) {
      // 旧格式（全局一份）：默认两项照旧，自建的环境只放进实际用到它的分组
      const base = e.filter(okEnv);
      const custom = base.filter((x) => x.id !== 'prod' && x.id !== 'test');
      const def = defaultEnvs().filter((d) => base.some((x) => x.id === d.id)).map((d) => base.find((x) => x.id === d.id));
      for (const c of custom) {
        for (const g of new Set(accounts.filter((a) => a.env === c.id).map((a) => a.groupId || ''))) {
          if (!envsBy[g]) envsBy[g] = def.map((x) => ({ ...x }));
          envsBy[g].push({ ...c });
        }
      }
      if (def.length !== 2) for (const g of ['', ...groups.map((x) => x.id)]) if (!envsBy[g]) envsBy[g] = def.map((x) => ({ ...x }));
      saveEnvs();
    } else if (e && typeof e === 'object') {
      for (const k of Object.keys(e)) if (Array.isArray(e[k])) envsBy[k] = e[k].filter(okEnv);
    }
  }
  const saveEnvs = () => writeJSON(K_ENVS, envsBy);
  const envsOf = (g) => envsBy[g || ''] || defaultEnvs();
  function ensureEnvs(g) { g = g || ''; if (!envsBy[g]) envsBy[g] = defaultEnvs(); return envsBy[g]; }
  // 「常用」「搜索」会跨分组，用所有分组环境的并集（同名只算一个）
  function allEnvs() {
    const seen = new Set(), out = [];
    for (const l of [defaultEnvs(), ...Object.values(envsBy)]) for (const e of l) if (!seen.has(e.id)) { seen.add(e.id); out.push(e); }
    return out;
  }
  // g 不传：在所有分组里找名字
  const envName = (id, g) => {
    const e = (g === undefined ? allEnvs() : envsOf(g)).find((x) => x.id === id);
    return e ? e.name : '';
  };
  const envColor = (id) => (id === 'prod' ? 'var(--n-danger)' : id === 'test' ? 'var(--n-ok)' : 'hsl(' + hue(id) + ' 62% 48%)');
  function makeEnv(g) {
    const v = prompt('给「' + groupName(g || '') + '」新建环境（例如 预发、开发）', '');
    if (v === null) return null;
    const name = v.trim();
    if (!name || envsOf(g).some((e) => e.name === name)) { toast('环境名称不能为空或重复', true); return null; }
    const e = { id: 'e' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6), name };
    ensureEnvs(g).push(e);
    saveEnvs();
    return e;
  }
  // 账号换了分组后：环境在新分组里没有就按名称对上，对不上就取消标记
  function fixEnv(a) {
    if (!a.env) return;
    const list = envsOf(a.groupId || '');
    if (list.some((e) => e.id === a.env)) return;
    const nm = envName(a.env);
    const m = nm && list.find((e) => e.name === nm);
    if (m) a.env = m.id; else delete a.env;
  }
  loadEnvs();
  const saveBoard = () => writeJSON(K_BOARD, accounts);
  const saveGroups = () => writeJSON(K_GROUPS, groups);

  const prefs = readJSON(K_PREFS, {}) || {};
  let filter = typeof prefs.filter === 'string' ? prefs.filter : 'all';
  let sort = ['custom', 'recent', 'name'].includes(prefs.sort) ? prefs.sort : 'custom';
  let mask = !!prefs.mask;
  // 每个分组各自记住自己的环境筛选：key 是 'g:分组id'（'g:' 为未分组）或 'fav'
  let envBy = prefs.envBy && typeof prefs.envBy === 'object' ? prefs.envBy : {};
  const savePrefs = () => writeJSON(K_PREFS, { filter, sort, mask, envBy });
  const envListFor = (key) => (key === 'fav' ? allEnvs() : envsOf(key.slice(2)));
  const getEnvF = (key) => { const v = envBy[key]; return v && v !== 'all' && envListFor(key).some((e) => e.id === v) ? v : 'all'; };
  function setEnvF(key, v) { envBy[key] = v; activeIdx = -1; savePrefs(); render(); }

  let query = '';
  let visible = [];      // 当前渲染顺序里的账号
  let activeIdx = -1;    // 键盘选中行
  let quick = null;      // 临时出码的账号（不保存）
  let dragging = false;  // 正在拖动排序
  let lastDragEnd = 0;   // 刚拖完的一瞬间不要当成点击
  let canSort = false;   // 当前视图是否允许拖动（默认顺序且不在搜索中）

  const gid = (a) => (a.groupId && groups.some((g) => g.id === a.groupId) ? a.groupId : '');
  const groupName = (id) => (id ? (groups.find((g) => g.id === id) || {}).name || '' : '未分组');
  function validFilter() {
    if (filter === 'all' || filter === 'fav' || filter === 'g:') return;
    if (!(filter.startsWith('g:') && groups.some((g) => 'g:' + g.id === filter))) filter = 'all';
  }
  validFilter();

  /* ---------- DOM 骨架 ---------- */
  const P = {
    search: '<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>',
    copy: '<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/>',
    qr: '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><path d="M14 14h3v3h-3zM21 14v.01M14 21h.01M17 21h4v-4"/>',
    edit: '<path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"/>',
    plus: '<path d="M12 5v14M5 12h14"/>',
    list: '<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>',
    x: '<path d="M18 6 6 18M6 6l12 12"/>',
    check: '<path d="M5 12.5l4.5 4.5L19 7.5"/>',
    more: '<circle cx="5" cy="12" r="1"/><circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/>',
    swap: '<path d="M7 7h13l-4-4M17 17H4l4 4"/>',
    bolt: '<path d="M13 2 4 14h7l-1 8 9-12h-7Z"/>',
    upload: '<path d="M12 15V3M7 8l5-5 5 5M5 21h14"/>',
    trash: '<path d="M3 6h18M8 6V4h8v2M6 6l1 14h10l1-14"/>',
    eye: '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/>',
    eyeoff: '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/><path d="M3 3l18 18"/>',
    grip: '<path d="M9 5h.01M15 5h.01M9 12h.01M15 12h.01M9 19h.01M15 19h.01"/>',
  };
  const svg = (p, s) => '<svg viewBox="0 0 24 24" width="' + (s || 16) + '" height="' + (s || 16) +
    '" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + P[p] + '</svg>';

  root.innerHTML = `
<div class="n-app" id="nApp">
  <header class="n-top">
    <div class="n-brand">
      <span class="n-logo">${svg('check', 18)}</span>
      <div><b>2FA 验证码</b><small>本地计算 · 密钥不上传</small></div>
    </div>
    <label class="n-search">
      ${svg('search')}
      <input id="nQ" type="search" placeholder="搜索账号或分组…" autocomplete="off" spellcheck="false" aria-label="搜索账号">
      <button type="button" class="n-search-clear" id="nQClear" aria-label="清空搜索" hidden>${svg('x', 14)}</button>
      <kbd>/</kbd>
    </label>
    <div class="n-top-actions">
      <button type="button" class="n-btn n-primary" id="nAdd">${svg('plus')}<span>添加</span></button>
      <div class="n-menu-wrap">
        <button type="button" class="n-btn n-icon" id="nMore" aria-haspopup="menu" aria-expanded="false" title="更多">${svg('more', 18)}</button>
        <div class="n-menu" id="nMoreMenu" role="menu" hidden>
          <button type="button" role="menuitem" data-act="quick">${svg('bolt')}临时出码（不保存）</button>
          <button type="button" role="menuitem" data-act="bulk">${svg('upload')}批量导入</button>
          <button type="button" role="menuitem" data-act="export">${svg('copy')}复制全部书签链接</button>
          <button type="button" role="menuitem" data-act="envs">${svg('list')}管理环境（每个分组各自的）</button>
          <hr>
          <button type="button" role="menuitem" data-act="clear" class="n-menu-danger">${svg('trash')}清空全部账号</button>
        </div>
      </div>
      <button type="button" class="n-btn n-ghost" id="nToOld" title="切换回旧版界面（数据共用）">${svg('swap')}<span>旧版</span></button>
    </div>
  </header>

  <div class="n-body">
    <nav class="n-side" id="nSide" aria-label="分组筛选"></nav>
    <main class="n-main">
      <div class="n-main-head">
        <div><h2 id="nTitle"></h2><span class="n-count" id="nCount"></span></div>
        <div class="n-head-right">
          <button type="button" class="n-btn" id="nMask" aria-pressed="false" title="隐藏 / 显示所有验证码（鼠标所在或选中的那行仍会显示）"></button>
          <select class="n-select" id="nSort" aria-label="排序">
            <option value="custom">默认顺序</option>
            <option value="recent">最近使用</option>
            <option value="name">名称 A–Z</option>
          </select>
          <div class="n-ring" title="当前验证码剩余秒数">
            <svg viewBox="0 0 36 36"><circle class="n-ring-bg" cx="18" cy="18" r="15.5"/><circle class="n-ring-fg" id="nRingFg" cx="18" cy="18" r="15.5"/></svg>
            <span id="nSec">30</span>
          </div>
        </div>
      </div>
      <div id="nEnv"></div>
      <div class="n-list" id="nList"></div>
      <p class="n-tip">快捷键：<kbd>/</kbd> 搜索 · <kbd>↑</kbd><kbd>↓</kbd> 选择 · <kbd>Enter</kbd> 复制验证码 · <kbd>Esc</kbd> 清空搜索。点任意一行即可复制验证码，点 ☆ 收藏到「常用」。按住左侧 ⋮⋮ 拖动调整顺序，拖到左边的分组上可换分组。每个分组右上角都有自己的环境切换条；把一行拖到切换条的某个环境上，就能直接标记。</p>
    </main>
  </div>

  <dialog class="n-dlg" id="nDlgAdd" aria-labelledby="nDlgAddTitle">
    <div class="n-dlg-head"><h3 id="nDlgAddTitle">添加账号</h3><button type="button" class="n-act" data-close aria-label="关闭">${svg('x')}</button></div>
    <div class="n-tabs" role="tablist">
      <button type="button" class="n-tab" data-tab="one" role="tab">单个添加</button>
      <button type="button" class="n-tab" data-tab="bulk" role="tab">批量导入</button>
      <button type="button" class="n-tab" data-tab="quick" role="tab">临时出码</button>
    </div>
    <div data-pane="one">
      <div class="n-dlg-body">
        <div class="n-field"><label for="nAddLabel">账号名称</label><input class="n-input" id="nAddLabel" placeholder="例如 GitHub" spellcheck="false" autocomplete="off"></div>
        <div class="n-field"><label for="nAddSecret">密钥 / SECRET</label><textarea class="n-input" id="nAddSecret" rows="2" placeholder="Base32 密钥，或 otpauth:// 链接（会自动识别名称）" spellcheck="false" autocomplete="off"></textarea></div>
        <div class="n-field"><div class="n-label">所属分组</div><div class="n-chips" id="nAddGroup" role="radiogroup" aria-label="所属分组"></div></div>
        <div class="n-field"><div class="n-label">环境</div><div class="n-chips" id="nAddEnv" role="radiogroup" aria-label="环境"></div></div>
        <div class="n-field"><label class="n-check"><input type="checkbox" id="nAddFav"> 加入「常用」</label></div>
        <div class="n-err" id="nAddErr" hidden></div>
      </div>
      <div class="n-dlg-foot"><button type="button" class="n-btn" data-close>取消</button><button type="button" class="n-btn n-primary" id="nAddOk">添加</button></div>
    </div>
    <div data-pane="bulk">
      <div class="n-dlg-body">
        <div class="n-field"><label for="nBulk">每行一个</label><textarea class="n-input" id="nBulk" rows="6" placeholder="密钥&#10;otpauth://totp/GitHub?secret=…&#10;#secret=xxx&amp;label=名称" spellcheck="false"></textarea></div>
        <div class="n-field"><div class="n-label">导入到分组</div><div class="n-chips" id="nBulkGroup" role="radiogroup" aria-label="导入到分组"></div></div>
        <div class="n-field"><div class="n-label">环境（不标记时，名称带「测试」的会自动标成测试）</div><div class="n-chips" id="nBulkEnv" role="radiogroup" aria-label="环境"></div></div>
        <div class="n-err" id="nBulkErr" hidden></div>
      </div>
      <div class="n-dlg-foot"><button type="button" class="n-btn" data-close>取消</button><button type="button" class="n-btn n-primary" id="nBulkOk">导入</button></div>
    </div>
    <div data-pane="quick">
      <div class="n-dlg-body">
        <p class="n-hint" style="margin-top:0">只在这里临时算一次验证码，不会保存到账号列表。</p>
        <div class="n-field"><label for="nQuickSecret">密钥 / SECRET</label><textarea class="n-input" id="nQuickSecret" rows="2" placeholder="粘贴 Base32 密钥，或 otpauth:// 链接" spellcheck="false" autocomplete="off"></textarea></div>
        <div class="n-field"><label for="nQuickLabel">账号名称（可选）</label><input class="n-input" id="nQuickLabel" placeholder="例如 GitHub" spellcheck="false" autocomplete="off"></div>
        <div class="n-err" id="nQuickErr" hidden></div>
        <div class="n-quick-res" id="nQuickRes" hidden>
          <div class="n-quick-top">
            <button type="button" class="n-code" id="nQuickCode" data-kind="code" title="点击复制">··· ···</button>
            <span class="n-cnt" id="nQuickSec"></span>
          </div>
          <div class="n-quick-acts">
            <button type="button" class="n-btn" id="nQuickBm">复制书签链接</button>
            <button type="button" class="n-btn" id="nQuickOtp">复制 otpauth</button>
            <button type="button" class="n-btn" id="nQuickQr">二维码</button>
            <button type="button" class="n-btn" id="nQuickSave">保存到列表</button>
          </div>
        </div>
      </div>
      <div class="n-dlg-foot"><button type="button" class="n-btn" data-close>关闭</button><button type="button" class="n-btn n-primary" id="nQuickGo">生成验证码</button></div>
    </div>
  </dialog>

  <dialog class="n-dlg" id="nDlgEdit" aria-labelledby="nDlgEditTitle">
    <div class="n-dlg-head"><h3 id="nDlgEditTitle">编辑账号</h3><button type="button" class="n-act" data-close aria-label="关闭">${svg('x')}</button></div>
    <div class="n-dlg-body">
      <div class="n-field"><label for="nEditLabel">账号名称</label><input class="n-input" id="nEditLabel" spellcheck="false" autocomplete="off"></div>
      <div class="n-field"><label for="nEditSecret">密钥 / SECRET</label><input class="n-input" id="nEditSecret" spellcheck="false" autocomplete="off" style="font-family:var(--n-mono);font-size:13px"></div>
      <div class="n-field"><div class="n-label">所属分组</div><div class="n-chips" id="nEditGroup" role="radiogroup" aria-label="所属分组"></div></div>
      <div class="n-field"><div class="n-label">环境</div><div class="n-chips" id="nEditEnv" role="radiogroup" aria-label="环境"></div></div>
      <div class="n-field"><label class="n-check"><input type="checkbox" id="nEditFav"> 常用</label></div>
      <div class="n-err" id="nEditErr" hidden></div>
    </div>
    <div class="n-dlg-foot">
      <button type="button" class="n-btn n-danger n-spacer" id="nEditDel">删除</button>
      <button type="button" class="n-btn" data-close>取消</button>
      <button type="button" class="n-btn n-primary" id="nEditOk">保存</button>
    </div>
  </dialog>

  <dialog class="n-dlg" id="nDlgQr" aria-labelledby="nQrTitle" style="width:min(360px,calc(100vw - 24px))">
    <div class="n-dlg-head"><h3 id="nQrTitle">二维码</h3><button type="button" class="n-act" data-close aria-label="关闭">${svg('x')}</button></div>
    <div class="n-dlg-body n-qr">
      <img id="nQrImg" alt="otpauth 二维码">
      <p>可用 Authenticator 等 App 扫码导入（含密钥，勿公开分享）</p>
      <div class="n-mono-box" id="nQrText"></div>
    </div>
    <div class="n-dlg-foot"><button type="button" class="n-btn" id="nQrCopy">复制 otpauth 链接</button><button type="button" class="n-btn n-primary" data-close>关闭</button></div>
  </dialog>

  <dialog class="n-dlg" id="nDlgEnv" aria-labelledby="nEnvTitle" style="width:min(420px,calc(100vw - 24px))">
    <div class="n-dlg-head"><h3 id="nEnvTitle">管理环境</h3><button type="button" class="n-act" data-close aria-label="关闭">${svg('x')}</button></div>
    <div class="n-dlg-body"><div class="n-field"><div class="n-label">选择分组（每个分组的环境各管各的）</div><div class="n-chips" id="nEnvGroup" role="radiogroup" aria-label="分组"></div></div><div id="nEnvList"></div><p class="n-hint" style="margin:10px 0 0">删除环境后，该分组里已标记它的账号会变成「不标记」，账号本身不会被删除。</p></div>
    <div class="n-dlg-foot"><button type="button" class="n-btn" id="nEnvNew">${svg('plus')}新建环境</button><button type="button" class="n-btn n-primary" data-close>完成</button></div>
  </dialog>

  <div class="n-toast" id="nToast" role="status" aria-live="polite"></div>
</div>`;

  const $ = (id) => document.getElementById(id);
  const el = (tag, cls, text) => {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  };
  const app = $('nApp');
  function renderMask() {
    app.classList.toggle('n-mask', mask);
    const b = $('nMask');
    b.setAttribute('aria-pressed', String(mask));
    b.innerHTML = svg(mask ? 'eyeoff' : 'eye', 15) + '<span>' + (mask ? '码已隐藏' : '隐藏验证码') + '</span>';
  }
  $('nMask').onclick = () => { mask = !mask; savePrefs(); renderMask(); };
  renderMask();
  const qInput = $('nQ');

  /* ---------- 提示条 ---------- */
  let toastTimer = 0;
  function toast(text, isErr) {
    const t = $('nToast');
    if (!t) return;
    t.textContent = text;
    t.classList.toggle('err', !!isErr);
    t.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => t.classList.remove('show'), isErr ? 3200 : 1800);
  }
  function showErr(id, text) { const e = $(id); e.textContent = text || ''; e.hidden = !text; }

  /* ---------- 验证码计算（全部账号共用一个 30 秒节拍） ---------- */
  const codes = new Map(); // secret -> { c, code, next }
  let curCounter = Math.floor(Date.now() / 1000 / PERIOD);
  function paintCodes() {
    for (const node of root.querySelectorAll('[data-secret]')) {
      const e = codes.get(node.dataset.secret);
      const ready = e && e.c === curCounter;
      if (node.dataset.kind === 'next') {
        node.textContent = ready && e.next ? '下一个 ' + fmt(e.next) : '';
        continue;
      }
      if (!ready) { node.textContent = '··· ···'; node.classList.remove('bad'); continue; }
      node.textContent = e.code ? fmt(e.code) : '密钥无效';
      node.classList.toggle('bad', !e.code);
    }
  }
  async function ensureCodes() {
    const counter = Math.floor(Date.now() / 1000 / PERIOD);
    curCounter = counter;
    const need = new Set(accounts.map((a) => a.secret));
    if (quick) need.add(quick.secret);
    const todo = [...need].filter((s) => { const e = codes.get(s); return !e || e.c !== counter; });
    if (!todo.length) return;
    await Promise.all(todo.map(async (s) => {
      let code = null, next = null;
      try { [code, next] = await Promise.all([hotp(s, counter), hotp(s, counter + 1)]); } catch (_) {}
      codes.set(s, { c: counter, code, next });
    }));
    if (counter === curCounter) paintCodes();
  }
  function currentCode(secret) {
    const e = codes.get(secret);
    return e && e.c === Math.floor(Date.now() / 1000 / PERIOD) ? e.code : null;
  }

  function copyAccount(a, codeEl) {
    const code = currentCode(a.secret);
    if (!code) { toast(codes.get(a.secret) && codes.get(a.secret).code === null ? '密钥无效，请编辑后重试' : '验证码尚未生成，请稍后重试', true); return; }
    copyText(code).then(() => {
      toast('已复制「' + (a.label || '未命名') + '」' + (a.env && envName(a.env, gid(a)) ? '（' + envName(a.env, gid(a)) + '）' : '') + ' ' + fmt(code));
      if (accounts.includes(a)) { a.used = Date.now(); saveBoard(); }
      if (codeEl) {
        const rowEl = codeEl.closest('.n-row');
        codeEl.classList.add('copied');
        if (rowEl) rowEl.classList.add('n-flash');
        setTimeout(() => { codeEl.classList.remove('copied'); if (rowEl) rowEl.classList.remove('n-flash'); }, 1000);
      }
    }).catch(() => toast('复制失败，请检查浏览器剪贴板权限或使用 HTTPS', true));
  }

  /* ---------- 侧栏 ---------- */
  function hue(str) { let h = 0; for (const ch of str) h = (h * 31 + ch.codePointAt(0)) >>> 0; return h % 360; }
  function dot(id) {
    const d = el('span', 'n-dot');
    d.style.background = id ? 'hsl(' + hue(id) + ' 62% 55%)' : 'var(--n-faint)';
    return d;
  }
  function navBtn(f, icon, label, n) {
    const b = el('button', 'n-nav');
    b.type = 'button';
    b.dataset.f = f;
    if (filter === f && !query.trim()) { b.classList.add('on'); b.setAttribute('aria-current', 'true'); }
    const ic = el('span', 'n-nav-ic');
    if (typeof icon === 'string') ic.innerHTML = icon; else ic.appendChild(icon);
    if (f === 'fav') ic.classList.add('n-star-ic');
    b.append(ic, el('span', 'n-nav-label', label), el('span', 'n-cnt', String(n)));
    b.onclick = () => setFilter(f);
    return b;
  }
  function miniBtn(html, title, onclick, danger) {
    const b = el('button', 'n-mini' + (danger ? ' n-mini-danger' : ''));
    b.type = 'button'; b.title = title; b.setAttribute('aria-label', title);
    b.innerHTML = html;
    b.onclick = (e) => { e.stopPropagation(); onclick(); };
    return b;
  }
  function renderSide() {
    const side = $('nSide');
    side.replaceChildren();
    const cnt = (fn) => accounts.filter(fn).length;
    side.append(
      navBtn('fav', '★', '常用', cnt((a) => a.fav)),
      navBtn('all', svg('list'), '全部账号', accounts.length)
    );
    const title = el('div', 'n-side-title');
    title.append(el('span', '', '分组'), miniBtn(svg('plus', 14), '新建分组', newGroup));
    side.appendChild(title);
    for (const g of groups) {
      const wrap = el('div', 'n-grp');
      if (filter === 'g:' + g.id) wrap.classList.add('cur');
      const acts = el('span', 'n-grp-acts');
      acts.append(
        miniBtn(svg('edit', 13), '重命名分组', () => renameGroup(g)),
        miniBtn(svg('x', 13), '删除分组', () => deleteGroup(g), true)
      );
      wrap.append(navBtn('g:' + g.id, dot(g.id), g.name, cnt((a) => gid(a) === g.id)), acts);
      side.appendChild(wrap);
    }
    side.appendChild(navBtn('g:', dot(''), '未分组', cnt((a) => !gid(a))));
    const addChip = miniBtn(svg('plus', 14), '新建分组', newGroup);
    addChip.classList.add('n-side-add');
    side.appendChild(addChip);
    const foot = el('div', 'n-side-foot', '数据只保存在本机浏览器。新旧界面共用同一份数据。');
    side.appendChild(foot);
  }

  function setFilter(f) {
    filter = f;
    query = '';
    qInput.value = '';
    activeIdx = -1;
    savePrefs();
    render();
  }
  function makeGroup() {
    const v = prompt('新分组名称', '');
    if (v === null) return null;
    const name = v.trim();
    if (!name || groups.some((g) => g.name === name)) { toast('分组名称不能为空或重复', true); return null; }
    const g = { id: 'g' + Date.now().toString(36) + Math.random().toString(36).slice(2, 7), name };
    groups.push(g);
    saveGroups();
    return g;
  }
  function newGroup() {
    const g = makeGroup();
    if (!g) return;
    setFilter('g:' + g.id);
    toast('已创建分组「' + g.name + '」');
  }
  function renameGroup(g) {
    const v = prompt('分组名称', g.name);
    if (v === null) return;
    const name = v.trim();
    if (!name || groups.some((x) => x !== g && x.name === name)) { toast('分组名称无效或重复', true); return; }
    g.name = name;
    saveGroups();
    render();
  }
  function deleteGroup(g) {
    if (!confirm('删除分组「' + g.name + '」？其中的账号会移到「未分组」，不会被删除。')) return;
    accounts.forEach((a) => { if (a.groupId === g.id) { a.groupId = ''; fixEnv(a); } });
    delete envsBy[g.id]; saveEnvs();
    groups = groups.filter((x) => x !== g);
    saveGroups(); saveBoard();
    if (filter === 'g:' + g.id) filter = 'all';
    savePrefs();
    render();
    toast('已删除分组');
  }

  /* ---------- 列表 ---------- */
  function sortList(list) {
    if (sort === 'name') return list.slice().sort((a, b) => (a.label || '').localeCompare(b.label || '', 'zh-CN', { numeric: true }));
    if (sort === 'recent') return list.slice().sort((a, b) => (b.used || 0) - (a.used || 0));
    return list;
  }
  // 搜索：空格分隔多个词，每个词都要命中（名称 / 分组名 / 环境），例如「github 测试」
  function searchList(tokens) {
    const scored = [];
    accounts.forEach((a, i) => {
      const name = (a.label || '').toLowerCase();
      const grp = groupName(gid(a)).toLowerCase();
      const en = a.env ? envName(a.env, gid(a)) : '';
      const env = en ? en + (a.env === 'prod' || a.env === 'test' ? ' ' + a.env : '') : '';
      let worst = 0;
      for (const t of tokens) {
        const s = name === t ? 0 : name.startsWith(t) ? 1 : name.includes(t) ? 2 : (grp.includes(t) || env.includes(t)) ? 3 : -1;
        if (s < 0) { worst = -1; break; }
        worst = Math.max(worst, s);
      }
      if (worst >= 0) scored.push({ a, s: worst, i });
    });
    scored.sort((x, y) => x.s - y.s || (sort === 'recent' ? (y.a.used || 0) - (x.a.used || 0) : 0) || x.i - y.i);
    return scored.map((x) => x.a);
  }
  function highlight(node, text, tokens) {
    if (!tokens || !tokens.length) { node.textContent = text; return; }
    const lower = text.toLowerCase();
    const marks = new Uint8Array(text.length);
    for (const t of tokens) {
      if (!t) continue;
      let at = -1;
      while ((at = lower.indexOf(t, at + 1)) >= 0) marks.fill(1, at, at + t.length);
    }
    for (let i = 0; i < text.length;) {
      let j = i;
      while (j < text.length && marks[j] === marks[i]) j++;
      const seg = text.slice(i, j);
      node.append(marks[i] ? el('mark', '', seg) : seg);
      i = j;
    }
  }

  function buildRow(a, showGroup, q) {
    const vi = visible.length;
    visible.push(a);
    const row = el('div', 'n-row');
    row.dataset.vi = String(vi);
    row._acc = a;

    const star = el('button', 'n-star' + (a.fav ? ' on' : ''), a.fav ? '★' : '☆');
    star.type = 'button';
    star.title = a.fav ? '取消常用' : '加入常用';
    star.setAttribute('aria-pressed', String(!!a.fav));
    star.onclick = () => {
      if (a.fav) delete a.fav; else a.fav = true;
      saveBoard();
      if (filter === 'fav' && !query.trim()) { render(); return; }
      star.textContent = a.fav ? '★' : '☆';
      star.classList.toggle('on', !!a.fav);
      star.title = a.fav ? '取消常用' : '加入常用';
      star.setAttribute('aria-pressed', String(!!a.fav));
      renderSide();
    };

    const info = el('div', 'n-info');
    const nameRow = el('div', 'n-namerow');
    const name = el('div', 'n-name');
    name.title = a.label || '未命名';
    highlight(name, a.label || '未命名', q);
    nameRow.appendChild(name);
    if (a.env && envName(a.env, gid(a))) {
      row.dataset.env = a.env;
      const tag = el('span', 'n-env', envName(a.env, gid(a)));
      tag.style.setProperty('--ec', envColor(a.env));
      nameRow.appendChild(tag);
    }
    info.appendChild(nameRow);
    if (showGroup) {
      const sub = el('div', 'n-sub');
      const pill = el('span', 'n-pill');
      const id = gid(a);
      pill.append(dot(id));
      highlight(pill, groupName(id), q);
      sub.appendChild(pill);
      info.appendChild(sub);
    }

    const box = el('div', 'n-codebox');
    const code = el('button', 'n-code', '··· ···');
    code.type = 'button';
    code.title = '点击复制验证码';
    code.dataset.secret = a.secret;
    code.dataset.kind = 'code';
    code.onclick = () => { setActive(vi, false); copyAccount(a, code); };
    const next = el('span', 'n-next');
    next.dataset.secret = a.secret;
    next.dataset.kind = 'next';
    box.append(code, next);

    const acts = el('div', 'n-acts');
    const act = (icon, title, fn) => {
      const b = el('button', 'n-act');
      b.type = 'button'; b.title = title; b.setAttribute('aria-label', title);
      b.innerHTML = svg(icon);
      b.onclick = fn;
      return b;
    };
    acts.append(
      act('copy', '复制验证码', () => copyAccount(a, code)),
      act('qr', '二维码', () => openQr(a)),
      act('edit', '编辑 / 删除', () => openEdit(a))
    );

    if (canSort) {
      const grip = el('button', 'n-grip');
      grip.type = 'button';
      grip.title = '按住拖动排序，可拖到左侧分组上换分组';
      grip.setAttribute('aria-label', '拖动排序');
      grip.innerHTML = svg('grip', 16);
      grip.addEventListener('pointerdown', (ev) => startDrag(ev, row, a));
      grip.addEventListener('contextmenu', (ev) => ev.preventDefault());
      row.appendChild(grip);
    }
    row.append(star, info, box, acts);
    // 点整行（名称、空白处都行）就复制验证码；星标、手柄、操作按钮各管各的
    row.addEventListener('click', (e) => {
      if (e.target.closest('button') || Date.now() - lastDragEnd < 400) return;
      setActive(vi, false);
      copyAccount(a, code);
    });
    return row;
  }

  // 某个分组（或「常用」）自己的环境切换条：全部 | 各环境（带数量）
  function envBar(key, scope, small) {
    const bar = el('div', 'n-envbar' + (small ? ' n-sm' : ''));
    bar.setAttribute('role', 'tablist');
    const cur = getEnvF(key);
    const add = (v, label, count, color) => {
      const b = el('button', 'n-seg' + (color ? ' n-seg-env' : '') + (cur === v ? ' on' : ''));
      b.type = 'button';
      b.dataset.env = v;
      if (key !== 'fav') b.dataset.gid = key.slice(2);
      b.setAttribute('role', 'tab');
      b.setAttribute('aria-selected', String(cur === v));
      if (color) b.style.setProperty('--ec', color);
      b.append(label, el('span', 'n-cnt', String(count)));
      b.onclick = () => setEnvF(key, v);
      bar.appendChild(b);
    };
    add('all', '全部', scope.length);
    for (const e of envListFor(key)) add(e.id, e.name, scope.filter((a) => a.env === e.id).length, envColor(e.id));
    if (key !== 'fav') {
      const g = key.slice(2);
      for (const [txt, tip, fn] of [['＋', '给这个分组新建环境', () => { const e = makeEnv(g); if (e) { render(); toast('已在「' + groupName(g) + '」新建环境「' + e.name + '」'); } }],
                                    ['管理', '管理这个分组的环境', () => openEnvMgr(g)]]) {
        const b = el('button', 'n-seg n-seg-tool', txt);
        b.type = 'button'; b.title = tip; b.onclick = fn;
        bar.appendChild(b);
      }
    }
    return bar;
  }

  function emptyState(title, text, buttons) {
    const box = el('div', 'n-empty');
    box.append(el('b', '', title), el('p', '', text));
    if (buttons && buttons.length) {
      const acts = el('div', 'n-empty-acts');
      for (const [label, fn, primary] of buttons) {
        const b = el('button', 'n-btn' + (primary ? ' n-primary' : ''), label);
        b.type = 'button'; b.onclick = fn; acts.appendChild(b);
      }
      box.appendChild(acts);
    }
    return box;
  }

  function render() {
    validFilter();
    renderSide();
    const list = $('nList');
    list.replaceChildren();
    visible = [];
    const q = query.trim().toLowerCase();
    const tokens = q ? q.split(/\s+/) : [];
    $('nSort').value = sort;
    $('nQClear').hidden = !query;
    canSort = sort === 'custom' && !q;
    list.classList.toggle('n-can-sort', canSort);

    const envHost = $('nEnv');
    envHost.replaceChildren();
    let title, items, key = null, scope = [], envF = 'all', secs = null;
    if (q) {
      title = '搜索“' + query.trim() + '”';
      items = searchList(tokens);
    } else if (filter === 'all') {
      // 全部：按分组分段，每段有自己的环境切换条
      title = '全部账号';
      secs = [];
      for (const id of [...groups.map((g) => g.id), '']) {
        const full = sortList(accounts.filter((a) => gid(a) === id));
        if (!full.length) continue;
        const f = getEnvF('g:' + id);
        secs.push({ id, full, f, rows: f === 'all' ? full : full.filter((a) => a.env === f) });
      }
      items = secs.flatMap((x) => x.rows);
    } else {
      if (filter === 'fav') { title = '常用'; scope = sortList(accounts.filter((a) => a.fav)); }
      else { const id = filter.slice(2); title = groupName(id); scope = sortList(accounts.filter((a) => gid(a) === id)); }
      key = filter;
      envF = getEnvF(key);
      items = envF === 'all' ? scope : scope.filter((a) => a.env === envF);
      envHost.appendChild(envBar(key, scope, false));
    }
    $('nTitle').textContent = title + (key && envF !== 'all' ? ' · ' + envName(envF, key === 'fav' ? undefined : key.slice(2)) : '');
    $('nCount').textContent = items.length + ' 个账号';

    if (!accounts.length) {
      list.appendChild(emptyState('还没有账号', '粘贴密钥或 otpauth:// 链接就能添加，数据只保存在本机浏览器。', [
        ['添加第一个账号', () => openAdd('one'), true],
        ['批量导入', () => openAdd('bulk')],
        ['临时出码', () => openAdd('quick')],
      ]));
    } else if (secs) {
      for (const sc of secs) {
        const wrap = el('section');
        const top = el('div', 'n-sec-top');
        const head = el('div', 'n-sec-head');
        const hb = el('button');
        hb.type = 'button';
        hb.title = '只看这个分组';
        hb.append(dot(sc.id), el('span', '', groupName(sc.id)), el('span', 'n-cnt', String(sc.rows.length)));
        hb.onclick = () => setFilter('g:' + sc.id);
        head.appendChild(hb);
        top.append(head, envBar('g:' + sc.id, sc.full, true));
        wrap.appendChild(top);
        if (sc.rows.length) {
          const rows = el('div', 'n-rows');
          rows.dataset.gid = sc.id;
          for (const a of sc.rows) rows.appendChild(buildRow(a, false, []));
          wrap.appendChild(rows);
        } else {
          wrap.appendChild(el('div', 'n-sec-empty', '这个分组里没有「' + envName(sc.f, sc.id) + '」账号'));
        }
        list.appendChild(wrap);
      }
    } else if (!items.length) {
      if (key && envF !== 'all' && scope.length) list.appendChild(emptyState('这里没有「' + envName(envF, key === 'fav' ? undefined : key.slice(2)) + '」账号', '在账号的「编辑」里选择环境，或把一行拖到上面的环境上，就会出现在这里。', [['查看全部', () => setEnvF(key, 'all')]]));
      else if (q) list.appendChild(emptyState('没有找到匹配的账号', '试试别的关键词，名称、分组名、环境名都能搜。', [['清空搜索', () => { qInput.value = ''; onQuery(); qInput.focus(); }]]));
      else if (filter === 'fav') list.appendChild(emptyState('还没有常用账号', '点击账号左侧的 ☆，就能把经常用的账号收藏到这里，打开就能找到。', [['查看全部账号', () => setFilter('all')]]));
      else list.appendChild(emptyState('这个分组还没有账号', '添加账号时选择这个分组，或在账号的「编辑」里把它移过来。', [['添加账号', () => openAdd('one'), true]]));
    } else {
      const rows = el('div', 'n-rows');
      const showGroup = !!q || filter === 'fav';
      for (const a of items) rows.appendChild(buildRow(a, showGroup, tokens));
      list.appendChild(rows);
    }
    if (activeIdx >= visible.length) activeIdx = visible.length - 1;
    updateActive(false);
    paintCodes();
    ensureCodes();
  }

  function setActive(i, scroll) { activeIdx = i; updateActive(scroll); }
  function updateActive(scroll) {
    for (const r of root.querySelectorAll('.n-row')) {
      const on = Number(r.dataset.vi) === activeIdx;
      r.classList.toggle('active', on);
      if (on && scroll) r.scrollIntoView({ block: 'nearest' });
    }
  }
  function moveActive(d) {
    if (!visible.length) return;
    activeIdx = activeIdx < 0 ? (d > 0 ? 0 : visible.length - 1) : Math.min(visible.length - 1, Math.max(0, activeIdx + d));
    updateActive(true);
  }
  function copyActive() {
    const i = activeIdx < 0 ? 0 : activeIdx;
    const a = visible[i];
    if (!a) return;
    const row = root.querySelector('.n-row[data-vi="' + i + '"]');
    setActive(i, true);
    copyAccount(a, row && row.querySelector('.n-code'));
  }

  /* ---------- 拖动排序 ---------- */
  // 按住行最左边的 ⋮⋮ 拖动：其他行实时让位；拖到别的分组区块里会换分组；
  // 拖到左侧「常用 / 分组」导航上松手 = 加入常用 / 移到该分组。鼠标和触屏都能用，Esc 取消。
  function startDrag(e, row, a) {
    if (dragging || (e.pointerType === 'mouse' && e.button !== 0)) return;
    e.preventDefault();
    dragging = true;
    const list = $('nList');
    const pid = e.pointerId;
    const grab = e.clientY - row.getBoundingClientRect().top;
    let px = e.clientX, py = e.clientY, navF = null, navEl = null, raf = 0;
    row.classList.add('n-dragging');
    list.classList.add('n-sorting');
    document.body.classList.add('n-grabbing');

    function pickContainer() {
      let best = null, bd = Infinity;
      for (const c of list.querySelectorAll('.n-rows')) {
        const r = c.getBoundingClientRect();
        const d = py < r.top ? r.top - py : py > r.bottom ? py - r.bottom : 0;
        if (d < bd) { bd = d; best = c; }
      }
      return best;
    }
    function reorder() {
      const c = pickContainer();
      if (!c) return;
      let ref = null;
      for (const s of c.children) {
        if (s === row) continue;
        const r = s.getBoundingClientRect();
        if (py < r.top + r.height / 2) { ref = s; break; }
      }
      const same = row.parentNode === c && (ref ? row.nextElementSibling === ref : row === c.lastElementChild);
      if (same) return;
      const others = [...list.querySelectorAll('.n-row')].filter((x) => x !== row);
      const before = new Map(others.map((x) => [x, x.getBoundingClientRect().top]));
      c.insertBefore(row, ref);
      for (const x of others) {
        const d = before.get(x) - x.getBoundingClientRect().top;
        if (d) x.animate([{ transform: 'translateY(' + d + 'px)' }, { transform: 'none' }], { duration: 150, easing: 'ease-out' });
      }
    }
    function hoverNav() {
      const t = document.elementFromPoint(px, py);
      const nav = t && t.closest ? t.closest('.n-nav, .n-seg') : null;
      let f = null;
      if (nav) {
        const nf = nav.dataset.f || (nav.dataset.env ? 'env:' + nav.dataset.env : '');
        if (nf === 'fav' ? !a.fav
          : nf.startsWith('env:') ? (nf !== 'env:all' && nf.slice(4) !== (a.env || '') && (nav.dataset.gid === undefined || nav.dataset.gid === gid(a)) && envsOf(gid(a)).some((e) => e.id === nf.slice(4)))
          : (nf.startsWith('g:') && nf.slice(2) !== gid(a))) f = nf;
      }
      const target = f ? nav : null;
      if (target !== navEl) {
        if (navEl) navEl.classList.remove('n-drop');
        if (target) target.classList.add('n-drop');
        navEl = target;
      }
      navF = f;
    }
    function frame() {
      // 靠近窗口上下边缘时自动滚动
      const top = 120, bot = window.innerHeight - 56;
      if (py < top) window.scrollBy(0, -Math.min(18, (top - py) / 5));
      else if (py > bot) window.scrollBy(0, Math.min(18, (py - bot) / 5));
      hoverNav();
      if (!navF) reorder();
      row.style.transform = '';
      row.style.transform = 'translateY(' + (py - grab - row.getBoundingClientRect().top) + 'px)';
      raf = requestAnimationFrame(frame);
    }
    function onMove(ev) { if (ev.pointerId === pid) { px = ev.clientX; py = ev.clientY; } }
    function onUp(ev) { if (ev.pointerId === pid) finish(false); }
    function onCancel(ev) { if (ev.pointerId === pid) finish(true); }
    function onKey(ev) { if (ev.key === 'Escape') { ev.preventDefault(); ev.stopPropagation(); finish(true); } }
    window.addEventListener('pointermove', onMove);
    window.addEventListener('pointerup', onUp);
    window.addEventListener('pointercancel', onCancel);
    window.addEventListener('keydown', onKey, true);

    function finish(cancel) {
      cancelAnimationFrame(raf);
      window.removeEventListener('pointermove', onMove);
      window.removeEventListener('pointerup', onUp);
      window.removeEventListener('pointercancel', onCancel);
      window.removeEventListener('keydown', onKey, true);
      dragging = false;
      lastDragEnd = Date.now();
      list.classList.remove('n-sorting');
      document.body.classList.remove('n-grabbing');
      row.style.transform = '';
      if (navEl) navEl.classList.remove('n-drop');
      if (cancel) { render(); return; }
      let msg = '';
      if (navF) {
        const idx = accounts.indexOf(a);
        if (idx >= 0) {
          if (navF === 'fav') { a.fav = true; msg = '已加入「常用」'; }
          else if (navF.startsWith('env:')) { a.env = navF.slice(4); msg = '已标记为「' + envName(a.env, gid(a)) + '」'; }
          else {
            a.groupId = navF.slice(2);
            fixEnv(a);
            accounts.splice(idx, 1);
            accounts.push(a);
            msg = '已移到「' + groupName(navF.slice(2)) + '」';
          }
        }
      } else {
        // 把当前可见账号按新的显示顺序，重新填回它们原来占的位置；跨区块拖动则同时换分组
        const els = [...list.querySelectorAll('.n-row')];
        const seq = els.map((r) => r._acc);
        const slots = seq.map((x) => accounts.indexOf(x));
        if (!slots.includes(-1)) {
          slots.sort((p, q) => p - q);
          for (const r of els) {
            const g = r.parentNode.dataset.gid;
            if (g !== undefined && g !== gid(r._acc)) { r._acc.groupId = g; fixEnv(r._acc); }
          }
          seq.forEach((x, i) => { accounts[slots[i]] = x; });
        }
      }
      saveBoard();
      render();
      activeIdx = visible.indexOf(a);
      updateActive(false);
      if (msg) toast(msg);
    }
    frame();
  }

  /* ---------- 搜索与快捷键 ---------- */
  function onQuery() {
    query = qInput.value;
    activeIdx = query.trim() ? 0 : -1;
    render();
  }
  qInput.addEventListener('input', onQuery);
  qInput.addEventListener('keydown', (e) => {
    if (e.isComposing) return;
    if (e.key === 'ArrowDown') { e.preventDefault(); moveActive(1); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); moveActive(-1); }
    else if (e.key === 'Enter') { e.preventDefault(); copyActive(); }
    else if (e.key === 'Escape') {
      e.preventDefault();
      if (qInput.value) { qInput.value = ''; onQuery(); } else qInput.blur();
    }
  });
  $('nQClear').onclick = () => { qInput.value = ''; onQuery(); qInput.focus(); };
  document.addEventListener('keydown', (e) => {
    if (dragging || root.querySelector('dialog[open]') || e.isComposing) return;
    const t = e.target;
    const typing = t && t.closest && t.closest('input, textarea, select, [contenteditable="true"]');
    if ((e.key === 'k' || e.key === 'K') && (e.metaKey || e.ctrlKey)) { e.preventDefault(); qInput.focus(); qInput.select(); return; }
    if (typing) return;
    if (e.key === '/') { e.preventDefault(); qInput.focus(); qInput.select(); }
    else if (e.key === 'ArrowDown' || e.key === 'ArrowUp') { e.preventDefault(); moveActive(e.key === 'ArrowDown' ? 1 : -1); }
    else if (e.key === 'Enter' && activeIdx >= 0 && !(t.closest && t.closest('button'))) { e.preventDefault(); copyActive(); }
    else if (e.key === 'Escape' && activeIdx >= 0) { setActive(-1, false); }
  });
  $('nSort').onchange = () => { sort = $('nSort').value; savePrefs(); render(); };

  /* ---------- 顶栏菜单 ---------- */
  const menu = $('nMoreMenu');
  function toggleMenu(open) {
    menu.hidden = !open;
    $('nMore').setAttribute('aria-expanded', String(open));
  }
  $('nMore').onclick = (e) => { e.stopPropagation(); toggleMenu(menu.hidden); };
  document.addEventListener('click', (e) => { if (!menu.hidden && !menu.contains(e.target)) toggleMenu(false); });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && !menu.hidden) toggleMenu(false); });
  menu.onclick = (e) => {
    const b = e.target.closest('button[data-act]');
    if (!b) return;
    toggleMenu(false);
    const act = b.dataset.act;
    if (act === 'envs') openEnvMgr(currentGroupId());
    else if (act === 'quick') openAdd('quick');
    else if (act === 'bulk') openAdd('bulk');
    else if (act === 'export') {
      if (!accounts.length) { toast('还没有账号', true); return; }
      copyText(accounts.map(bookmarkUrl).join('\n'))
        .then(() => toast('已复制 ' + accounts.length + ' 个账号的书签链接（含密钥，请妥善保存）'))
        .catch(() => toast('复制失败，请检查剪贴板权限', true));
    } else if (act === 'clear') {
      if (!accounts.length) { toast('列表已经是空的'); return; }
      if (!confirm('确定清空全部 ' + accounts.length + ' 个账号？此操作不可撤销，建议先「复制全部书签链接」备份。')) return;
      accounts = []; saveBoard(); render(); toast('已清空');
    }
  };
  let envMgrGid = '';
  function openEnvMgr(g) {
    envMgrGid = groups.some((x) => x.id === g) ? g : '';
    chipPicker($('nEnvGroup'), [...groups.map((x) => ({ v: x.id, label: x.name, dot: x.id })), { v: '', label: '未分组', dot: '' }], envMgrGid);
    $('nEnvGroup').onpick = (v) => { envMgrGid = v; renderEnvList(); };
    renderEnvList();
    if (!$('nDlgEnv').open) $('nDlgEnv').showModal();
  }
  function renderEnvList() {
    const box = $('nEnvList');
    box.replaceChildren();
    const list = envsOf(envMgrGid);
    if (!list.length) box.appendChild(el('p', 'n-hint', '这个分组还没有环境，点下面的「新建环境」添加。'));
    for (const e of list) {
      const used = accounts.filter((a) => gid(a) === envMgrGid && a.env === e.id).length;
      const row = el('div', 'n-envrow');
      row.dataset.id = e.id;
      const grip = el('button', 'n-grip');
      grip.type = 'button';
      grip.title = '按住拖动排序（也可聚焦后按 ↑ ↓）';
      grip.setAttribute('aria-label', '拖动排序');
      grip.innerHTML = svg('grip', 16);
      grip.addEventListener('pointerdown', (ev) => startEnvDrag(ev, row, box));
      grip.addEventListener('keydown', (ev) => {
        if (ev.key !== 'ArrowUp' && ev.key !== 'ArrowDown') return;
        ev.preventDefault();
        const sib = ev.key === 'ArrowUp' ? row.previousElementSibling : row.nextElementSibling;
        if (!sib || !sib.classList.contains('n-envrow')) return;
        if (ev.key === 'ArrowUp') box.insertBefore(row, sib); else box.insertBefore(sib, row);
        commitEnvOrder(box);
        const again = $('nEnvList').querySelector('.n-envrow[data-id="' + e.id + '"] .n-grip');
        if (again) again.focus();
      });
      const tag = el('span', 'n-env', e.name);
      tag.style.setProperty('--ec', envColor(e.id));
      const ren = el('button', 'n-btn', '重命名');
      ren.type = 'button';
      ren.onclick = () => {
        const v = prompt('环境名称', e.name);
        if (v === null) return;
        const name = v.trim();
        if (!name || list.some((x) => x !== e && x.name === name)) { toast('名称无效或重复', true); return; }
        const t = ensureEnvs(envMgrGid).find((x) => x.id === e.id);
        t.name = name; saveEnvs(); renderEnvList(); render();
      };
      const del = el('button', 'n-btn n-danger', '删除');
      del.type = 'button';
      del.onclick = () => {
        if (!confirm('删除「' + groupName(envMgrGid) + '」里的环境「' + e.name + '」？已标记它的 ' + used + ' 个账号会变成「不标记」。')) return;
        accounts.forEach((a) => { if (gid(a) === envMgrGid && a.env === e.id) delete a.env; });
        envsBy[envMgrGid || ''] = ensureEnvs(envMgrGid).filter((x) => x.id !== e.id);
        saveEnvs(); saveBoard(); renderEnvList(); render();
      };
      row.append(grip, tag, el('span', 'n-cnt n-spacer', used + ' 个账号'), ren, del);
      box.appendChild(row);
    }
  }
  // 按当前 DOM 顺序保存这个分组的环境顺序
  function commitEnvOrder(box) {
    const cur = ensureEnvs(envMgrGid);
    const order = [...box.querySelectorAll('.n-envrow')].map((r) => cur.find((x) => x.id === r.dataset.id)).filter(Boolean);
    if (order.length !== cur.length) return;
    envsBy[envMgrGid || ''] = order;
    saveEnvs();
    renderEnvList();
    render();
  }
  // 在管理对话框里拖动 ⋮⋮ 调整环境顺序（鼠标、触屏都可用）
  function startEnvDrag(ev, row, box) {
    if (ev.button !== undefined && ev.button !== 0) return;
    ev.preventDefault();
    row.classList.add('n-envrow-drag');
    const move = (e) => {
      for (const r of box.querySelectorAll('.n-envrow')) {
        if (r === row) continue;
        const b = r.getBoundingClientRect();
        if (e.clientY < b.top || e.clientY > b.bottom) continue;
        const before = e.clientY < b.top + b.height / 2;
        if (before && r.previousElementSibling !== row) box.insertBefore(row, r);
        else if (!before && r.nextElementSibling !== row) box.insertBefore(row, r.nextElementSibling);
        break;
      }
    };
    const end = () => {
      document.removeEventListener('pointermove', move);
      document.removeEventListener('pointerup', end);
      document.removeEventListener('pointercancel', end);
      row.classList.remove('n-envrow-drag');
      commitEnvOrder(box);
    };
    document.addEventListener('pointermove', move);
    document.addEventListener('pointerup', end);
    document.addEventListener('pointercancel', end);
  }
  $('nEnvNew').onclick = () => { const e = makeEnv(envMgrGid); if (e) { renderEnvList(); render(); toast('已创建环境「' + e.name + '」'); } };
  $('nAdd').onclick = () => openAdd('one');
  $('nToOld').onclick = () => {
    try { localStorage.setItem(K_UI, 'v1'); } catch (_) {}
    location.reload();
  };

  /* ---------- 弹窗通用 ---------- */
  for (const dlg of root.querySelectorAll('dialog')) {
    dlg.addEventListener('click', (e) => {
      if (e.target === dlg || e.target.closest('[data-close]')) dlg.close();
    });
  }
  // 单选标签组：点一下就选中，不用展开下拉框。box.value 是当前选中的值。
  function chipPicker(box, options, value, onNew, newLabel) {
    box.replaceChildren();
    box.value = value;
    const sync = () => {
      for (const b of box.children) {
        if (b.dataset.v === undefined) continue;
        const on = b.dataset.v === box.value;
        b.classList.toggle('on', on);
        b.setAttribute('aria-checked', String(on));
      }
    };
    for (const o of options) {
      const b = el('button', 'n-chip' + (o.color ? ' n-chip-env' : ''));
      if (o.color) b.style.setProperty('--ec', o.color);
      b.type = 'button';
      b.setAttribute('role', 'radio');
      b.dataset.v = o.v;
      if (o.dot !== undefined) b.appendChild(dot(o.dot));
      b.append(o.label);
      b.onclick = () => { box.value = o.v; sync(); if (box.onpick) box.onpick(o.v); };
      box.appendChild(b);
    }
    if (onNew) {
      const add = el('button', 'n-chip n-chip-new', newLabel || '＋ 新建分组');
      add.type = 'button';
      add.onclick = onNew;
      box.appendChild(add);
    }
    sync();
  }
  const GROUP_BOXES = ['nAddGroup', 'nBulkGroup', 'nEditGroup'];
  function fillGroups(box, selected) {
    const cur = groups.some((g) => g.id === selected) ? selected : '';
    chipPicker(box, [{ v: '', label: '未分组', dot: '' }, ...groups.map((g) => ({ v: g.id, label: g.name, dot: g.id }))], cur, () => {
      const g = makeGroup();
      if (!g) return;
      for (const id of GROUP_BOXES) { const b = $(id); fillGroups(b, b === box ? g.id : b.value); syncEnv(b); }
      renderSide();
      toast('已创建分组「' + g.name + '」');
    });
  }
  // 环境选择器跟着「所属分组」走：每个分组只显示自己的环境
  const ENV_OF = { nAddGroup: 'nAddEnv', nBulkGroup: 'nBulkEnv', nEditGroup: 'nEditEnv' };
  function fillEnv(box, selected, g) {
    g = g || '';
    const list = envsOf(g);
    const cur = list.some((e) => e.id === selected) ? selected : '';
    chipPicker(box, [{ v: '', label: '不标记' }, ...list.map((e) => ({ v: e.id, label: e.name, color: envColor(e.id) }))], cur, () => {
      const e = makeEnv(g);
      if (!e) return;
      for (const gb of Object.keys(ENV_OF)) {
        const eb = $(ENV_OF[gb]);
        if ($(gb).value === g) fillEnv(eb, eb === box ? e.id : eb.value, g);
      }
      if (box.id === 'nAddEnv') envTouched = true;
      render();
      toast('已在「' + groupName(g) + '」新建环境「' + e.name + '」');
    }, '＋ 新建环境');
  }
  const syncEnv = (gb) => { const eb = $(ENV_OF[gb.id]); fillEnv(eb, eb.value, gb.value); };
  for (const id of Object.keys(ENV_OF)) $(id).onpick = () => syncEnv($(id));
  // 新增账号时的默认环境：在某个分组里、且该分组正筛选着某个环境，就默认选它
  function defaultEnv() {
    const v = !query.trim() && filter !== 'all' ? getEnvF(filter) : 'all';
    return v === 'all' ? '' : v;
  }
  const currentGroupId = () => (filter.startsWith('g:') && !query.trim() ? filter.slice(2) : '');

  /* ---------- 添加 / 导入 / 临时出码 ---------- */
  const dlgAdd = $('nDlgAdd');
  function setTab(tab) {
    for (const b of dlgAdd.querySelectorAll('.n-tab')) {
      const on = b.dataset.tab === tab;
      b.classList.toggle('on', on);
      b.setAttribute('aria-selected', String(on));
    }
    for (const p of dlgAdd.querySelectorAll('[data-pane]')) p.hidden = p.dataset.pane !== tab;
    $('nDlgAddTitle').textContent = { one: '添加账号', bulk: '批量导入', quick: '临时出码' }[tab];
    const focus = { one: 'nAddLabel', bulk: 'nBulk', quick: 'nQuickSecret' }[tab];
    setTimeout(() => $(focus).focus(), 0);
  }
  for (const b of dlgAdd.querySelectorAll('.n-tab')) b.onclick = () => setTab(b.dataset.tab);
  let envTouched = false; // 手动选过环境后，不再按名称自动判断
  $('nAddEnv').onpick = () => { envTouched = true; };
  function autoEnv() {
    if (envTouched) return;
    const g = $('nAddGroup').value;
    fillEnv($('nAddEnv'), looksTest($('nAddLabel').value) && envsOf(g).some((e) => e.id === 'test') ? 'test' : defaultEnv(), g);
  }
  $('nAddLabel').addEventListener('input', autoEnv);
  function openAdd(tab, preset) {
    const g = currentGroupId();
    fillGroups($('nAddGroup'), g);
    fillGroups($('nBulkGroup'), g);
    envTouched = false;
    fillEnv($('nAddEnv'), defaultEnv(), g);
    fillEnv($('nBulkEnv'), defaultEnv(), g);
    $('nAddFav').checked = filter === 'fav' && !query.trim();
    showErr('nAddErr'); showErr('nBulkErr'); showErr('nQuickErr');
    if (preset) { $('nAddLabel').value = preset.label || ''; $('nAddSecret').value = preset.secret || ''; autoEnv(); }
    if (!dlgAdd.open) dlgAdd.showModal();
    setTab(tab);
  }
  dlgAdd.addEventListener('close', () => {
    // 临时出码不留痕：关闭后清掉地址栏里的密钥
    if (/secret=/.test(location.hash)) { try { history.replaceState(null, '', location.pathname + location.search); } catch (_) {} }
    quick = null;
    $('nQuickRes').hidden = true;
  });

  function addAccount() {
    const parsed = parseSecretInput($('nAddSecret').value);
    if (!parsed) { showErr('nAddErr', '密钥无效：请使用 Base32（A–Z / 2–7）或完整的 otpauth:// 链接'); return; }
    const label = ($('nAddLabel').value.trim() || parsed.label || '').trim();
    if (accounts.some((x) => x.secret === parsed.secret && (x.label || '') === label)) { showErr('nAddErr', '这个账号已经在列表里了'); return; }
    const acc = { secret: parsed.secret, label, groupId: $('nAddGroup').value };
    if ($('nAddEnv').value) acc.env = $('nAddEnv').value;
    if ($('nAddFav').checked) acc.fav = true;
    accounts.push(acc);
    saveBoard();
    $('nAddLabel').value = ''; $('nAddSecret').value = '';
    dlgAdd.close();
    render();
    toast('已添加「' + (label || '未命名') + '」');
  }
  $('nAddOk').onclick = addAccount;
  $('nAddLabel').addEventListener('keydown', (e) => { if (e.key === 'Enter' && !e.isComposing) { e.preventDefault(); $('nAddSecret').focus(); } });
  $('nAddSecret').addEventListener('keydown', (e) => { if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) { e.preventDefault(); addAccount(); } });
  $('nAddSecret').addEventListener('input', () => {
    // 粘贴 otpauth 链接时自动带出名称
    const p = parseSecretInput($('nAddSecret').value);
    if (p && p.label && !$('nAddLabel').value.trim()) { $('nAddLabel').value = p.label; autoEnv(); }
  });

  $('nBulkOk').onclick = () => {
    const groupId = $('nBulkGroup').value;
    const bulkEnv = $('nBulkEnv').value;
    let n = 0, bad = 0;
    for (const line of $('nBulk').value.split(/\r?\n/)) {
      if (!line.trim()) continue;
      const acc = parseSecretInput(line);
      if (!acc) { bad++; continue; }
      if (accounts.some((x) => x.secret === acc.secret && (x.label || '') === acc.label)) continue;
      acc.groupId = groupId;
      const env = bulkEnv || (looksTest(acc.label) && envsOf(groupId).some((e) => e.id === 'test') ? 'test' : '');
      if (env) acc.env = env;
      accounts.push(acc); n++;
    }
    if (!n) { showErr('nBulkErr', bad ? '没有识别到有效账号（' + bad + ' 行无效）' : '没有新账号（可能都已存在）'); return; }
    saveBoard();
    $('nBulk').value = '';
    dlgAdd.close();
    render();
    toast('已导入 ' + n + ' 个账号' + (bad ? '，' + bad + ' 行无效已跳过' : ''));
  };

  function runQuick() {
    const parsed = parseSecretInput($('nQuickSecret').value);
    if (!parsed) { showErr('nQuickErr', '密钥无效：请使用 Base32（A–Z / 2–7）'); $('nQuickRes').hidden = true; quick = null; return; }
    showErr('nQuickErr');
    parsed.label = ($('nQuickLabel').value.trim() || parsed.label || '').trim();
    if (!$('nQuickLabel').value.trim() && parsed.label) $('nQuickLabel').value = parsed.label;
    quick = parsed;
    $('nQuickCode').dataset.secret = parsed.secret;
    $('nQuickRes').hidden = false;
    paintCodes();
    ensureCodes();
    tick();
  }
  $('nQuickGo').onclick = runQuick;
  $('nQuickSecret').addEventListener('keydown', (e) => { if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) { e.preventDefault(); runQuick(); } });
  $('nQuickCode').onclick = () => { if (quick) copyAccount(quick, $('nQuickCode')); };
  $('nQuickBm').onclick = () => quick && copyText(bookmarkUrl(quick)).then(() => toast('书签链接已复制（含密钥，请妥善保存）'));
  $('nQuickOtp').onclick = () => quick && copyText(otpauthUrl(quick)).then(() => toast('otpauth 链接已复制'));
  $('nQuickQr').onclick = () => quick && openQr(quick);
  $('nQuickSave').onclick = () => { if (quick) openAdd('one', quick); };

  /* ---------- 编辑 ---------- */
  const dlgEdit = $('nDlgEdit');
  let editing = null;
  function openEdit(a) {
    editing = a;
    $('nEditLabel').value = a.label || '';
    $('nEditSecret').value = a.secret || '';
    fillGroups($('nEditGroup'), gid(a));
    fillEnv($('nEditEnv'), a.env || '', gid(a));
    $('nEditFav').checked = !!a.fav;
    showErr('nEditErr');
    dlgEdit.showModal();
    $('nEditLabel').focus();
  }
  $('nEditOk').onclick = () => {
    if (!editing || !accounts.includes(editing)) { dlgEdit.close(); return; }
    const parsed = parseSecretInput($('nEditSecret').value);
    if (!parsed) { showErr('nEditErr', '密钥无效：请使用 Base32（A–Z / 2–7）'); return; }
    editing.secret = parsed.secret;
    editing.label = $('nEditLabel').value.trim() || parsed.label || editing.label || '';
    editing.groupId = $('nEditGroup').value;
    if ($('nEditEnv').value) editing.env = $('nEditEnv').value; else delete editing.env;
    if ($('nEditFav').checked) editing.fav = true; else delete editing.fav;
    saveBoard();
    dlgEdit.close();
    render();
    toast('已保存');
  };
  $('nEditLabel').addEventListener('keydown', (e) => { if (e.key === 'Enter' && !e.isComposing) { e.preventDefault(); $('nEditOk').click(); } });
  $('nEditDel').onclick = () => {
    if (!editing) return;
    if (!confirm('删除「' + (editing.label || '未命名') + '」？此操作不可撤销。')) return;
    accounts = accounts.filter((x) => x !== editing);
    saveBoard();
    dlgEdit.close();
    render();
    toast('已删除');
  };

  /* ---------- 二维码 ---------- */
  const dlgQr = $('nDlgQr');
  let qrAcc = null;
  function openQr(a) {
    const url = otpauthUrl(a);
    const data = makeQrDataUrl(url);
    if (!data) { toast('二维码库未加载，请刷新页面', true); return; }
    qrAcc = a;
    $('nQrTitle').textContent = (a.label || '账号') + ' · 二维码';
    $('nQrImg').src = data;
    $('nQrText').textContent = url;
    dlgQr.showModal();
  }
  $('nQrCopy').onclick = () => qrAcc && copyText(otpauthUrl(qrAcc)).then(() => toast('otpauth 链接已复制'));

  /* ---------- 节拍 ---------- */
  function tick() {
    const now = Date.now() / 1000;
    const left = PERIOD - (now % PERIOD);
    const secs = Math.max(1, Math.ceil(left));
    $('nSec').textContent = String(secs);
    $('nRingFg').style.strokeDashoffset = String(RING * (1 - left / PERIOD));
    app.classList.toggle('urgent', secs <= 5);
    app.classList.toggle('soon', secs <= 8);
    $('nQuickSec').textContent = secs + ' 秒后刷新';
    if (Math.floor(now / PERIOD) !== curCounter) paintCodes();
    ensureCodes();
  }
  setInterval(tick, 250);

  // 其他标签页（包括旧版）改了数据时同步过来
  window.addEventListener('storage', (e) => {
    if (!dragging && (e.key === K_BOARD || e.key === K_GROUPS || e.key === K_ENVS)) { loadData(); loadEnvs(); render(); }
  });

  render();
  tick();
  // 电脑上打开即聚焦搜索框：直接打字 + Enter 就能复制（手机不自动聚焦，避免弹出键盘）
  if (!location.hash && window.matchMedia('(hover: hover) and (pointer: fine)').matches) qInput.focus();

  // 兼容旧版书签链接：#secret=xxx&label=yyy 打开即出码
  (function loadHash() {
    const raw = (location.hash || '').replace(/^#/, '');
    if (!raw) return;
    const parsed = parseSecretInput(raw.includes('secret=') ? raw : 'secret=' + raw);
    if (!parsed) return;
    const saved = accounts.find((a) => a.secret === parsed.secret);
    openAdd('quick');
    $('nQuickSecret').value = parsed.secret;
    $('nQuickLabel').value = parsed.label || (saved && saved.label) || '';
    runQuick();
  })();
})();
