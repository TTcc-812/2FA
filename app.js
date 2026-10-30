(function () {
  const A32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

  function b32decode(s) {
    s = (s || '').replace(/=+$/, '').replace(/\s/g, '').toUpperCase();
    if (!s || /[^A-Z2-7]/.test(s)) return null;
    let bits = 0, val = 0; const out = [];
    for (const ch of s) {
      const i = A32.indexOf(ch);
      if (i < 0) return null;
      val = (val << 5) | i; bits += 5;
      if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; }
    }
    return out.length ? new Uint8Array(out) : null;
  }

  async function totp(secret, digits = 6, period = 30) {
    const key = b32decode(secret);
    if (!key) throw new Error('invalid secret');
    const counter = Math.floor(Date.now() / 1000 / period);
    const buf = new ArrayBuffer(8);
    const dv = new DataView(buf);
    dv.setUint32(0, Math.floor(counter / 0x100000000));
    dv.setUint32(4, counter >>> 0);
    const ck = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
    const sig = new Uint8Array(await crypto.subtle.sign('HMAC', ck, buf));
    const off = sig[sig.length - 1] & 0x0f;
    const bin = ((sig[off] & 0x7f) << 24) | ((sig[off + 1] & 0xff) << 16) | ((sig[off + 2] & 0xff) << 8) | (sig[off + 3] & 0xff);
    return String(bin % 10 ** digits).padStart(digits, '0');
  }

  function parseSecretInput(raw) {
    raw = (raw || '').trim();
    if (!raw) return null;
    let secret = '', label = '';
    if (/^otpauth:\/\//i.test(raw)) {
      try {
        const u = new URL(raw);
        secret = (u.searchParams.get('secret') || '').trim();
        let path = decodeURIComponent(u.pathname.replace(/^\/+/, ''));
        if (path.includes(':')) label = path.split(':').slice(1).join(':').trim();
        else label = path;
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
    if (!acc || !acc.secret) return '';
    const label = encodeURIComponent(acc.label || 'account');
    const sp = new URLSearchParams();
    sp.set('secret', acc.secret);
    sp.set('issuer', '2FA');
    return 'otpauth://totp/' + label + '?' + sp.toString();
  }

  function makeQrDataUrl(text) {
    if (typeof qrcode === 'undefined') return null;
    try {
      const qr = qrcode(0, 'M');
      qr.addData(text);
      qr.make();
      return qr.createDataURL(5, 2);
    } catch (e) { return null; }
  }

  function bookmarkUrl(acc) {
    const sp = new URLSearchParams();
    sp.set('secret', acc.secret);
    if (acc.label) sp.set('label', acc.label);
    return location.origin + location.pathname + '#' + sp.toString();
  }

  function copyText(t) {
    if (navigator.clipboard && navigator.clipboard.writeText) return navigator.clipboard.writeText(t);
    const ta = document.createElement('textarea');
    ta.value = t; document.body.appendChild(ta); ta.select();
    const ok = document.execCommand('copy'); ta.remove();
    return ok ? Promise.resolve() : Promise.reject(new Error('浏览器未允许复制'));
  }

  function show(el, text, isErr) {
    el.textContent = text || '';
    el.classList.toggle('hidden', !text);
    el.classList.toggle('err', !!isErr);
  }

  let current = null;
  let accounts = [];
  let editIndex = -1;
  let qrVisible = false;
  try {
    accounts = JSON.parse(localStorage.getItem('simple2fa.board') || '[]') || [];
  } catch (e) { accounts = []; }

  const $ = (id) => document.getElementById(id);
  const panelSingle = $('panelSingle');
  const panelBoard = $('panelBoard');

  function saveBoard() {
    try { localStorage.setItem('simple2fa.board', JSON.stringify(accounts)); } catch (e) {}
  }

  function switchTab(board) {
    panelSingle.classList.toggle('hidden', board);
    panelBoard.classList.toggle('hidden', !board);
    $('tabSingle').classList.toggle('primary', !board);
    $('tabBoard').classList.toggle('primary', board);
    if (board) renderBoard();
  }

  $('tabSingle').onclick = () => switchTab(false);
  $('tabBoard').onclick = () => switchTab(true);

  async function refreshSingle() {
    if (!current) return;
    try {
      const account = current;
      const code = await totp(account.secret);
      if (current !== account) return;
      const period = 30;
      const left = Math.max(1, period - (Math.floor(Date.now() / 1000) % period));
      $('code').textContent = code.slice(0, 3) + ' ' + code.slice(3);
      $('timer').textContent = left + 's';
      $('bar').style.width = (left / period * 100) + '%';
      current._code = code;
    } catch (e) {
      show($('singleErr'), '密钥无效', true);
    }
  }

  function setSingle(acc) {
    current = acc;
    $('code').textContent = '······';
    $('secret').value = acc.secret;
    $('label').value = acc.label || '';
    $('singleResult').classList.remove('hidden');
    $('bookmark').textContent = bookmarkUrl(acc);
    $('otpauth').textContent = otpauthUrl(acc);
    show($('singleErr'), '');
    show($('singleMsg'), '');
    $('qrWrap').classList.add('hidden');
    qrVisible = false;
    $('btnShowQr').textContent = '显示二维码';
    refreshSingle();
    try { history.replaceState(null, '', bookmarkUrl(acc)); } catch (e) {}
  }

  // Clear an inherited label when the user switches to another secret.
  // A label explicitly edited by the user is left alone.
  $('secret').addEventListener('input', () => {
    if (current && $('secret').value.trim() !== current.secret &&
        $('label').value === (current.label || '')) {
      $('label').value = '';
    }
  });

  $('btnGen').onclick = () => {
    const acc = parseSecretInput($('secret').value);
    if (!acc) {
      show($('singleErr'), '密钥无效：请使用 Base32（A–Z / 2–7）', true);
      $('singleResult').classList.add('hidden');
      current = null;
      return;
    }
    acc.label = (acc.label || $('label').value || '').trim();
    setSingle(acc);
  };

  function copySingleCode() {
    const code = current && current._code;
    if (!code || !/^\d{6}$/.test(code)) {
      show($('singleMsg'), '验证码尚未生成，请稍后重试', true);
      return;
    }
    copyText(code).then(() => {
      show($('singleMsg'), '验证码已复制（完整6位）');
    }).catch(() => {
      show($('singleMsg'), '复制失败，请检查浏览器剪贴板权限或使用 HTTPS', true);
    });
  }

  $('btnCopyCode').onclick = copySingleCode;
  $('code').onclick = copySingleCode;
  $('code').onkeydown = (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      copySingleCode();
    }
  };

  $('btnCopyLink').onclick = async () => {
    if (!current) return;
    await copyText(bookmarkUrl(current));
    show($('singleMsg'), '书签链接已复制（含密钥，请妥善保存）');
  };

  $('btnCopyOtpauth').onclick = async () => {
    if (!current) return;
    await copyText(otpauthUrl(current));
    show($('singleMsg'), 'otpauth 链接已复制（可粘贴到 Authenticator 手动添加）');
  };

  $('btnShowQr').onclick = () => {
    if (!current) {
      show($('singleErr'), '请先生成验证码', true);
      return;
    }
    const wrap = $('qrWrap');
    if (qrVisible) {
      wrap.classList.add('hidden');
      qrVisible = false;
      $('btnShowQr').textContent = '显示二维码';
      return;
    }
    const url = otpauthUrl(current);
    const data = makeQrDataUrl(url);
    if (!data) {
      show($('singleErr'), '二维码库未加载，请刷新页面或确认 vendor/qrcode.js 存在', true);
      return;
    }
    $('qrImg').src = data;
    wrap.classList.remove('hidden');
    qrVisible = true;
    $('btnShowQr').textContent = '隐藏二维码';
  };

  $('btnAddToBoard').onclick = () => {
    if (!current) {
      const acc = parseSecretInput($('secret').value);
      if (!acc) {
        show($('singleErr'), '请先输入有效密钥', true);
        return;
      }
      acc.label = ($('label').value || acc.label || '').trim();
      current = acc;
    }
    const exists = accounts.some(x => x.secret === current.secret && x.label === (current.label || ''));
    if (exists) {
      show($('singleMsg'), '该账号已在看板中');
      return;
    }
    accounts.push({ secret: current.secret, label: current.label || '' });
    saveBoard();
    show($('singleMsg'), '已加入看板，可切换到「多账号看板」查看');
  };

  function addOneAccount(secretRaw, labelRaw) {
    const acc = parseSecretInput(secretRaw);
    if (!acc) return { ok: false, msg: '密钥无效：请使用 Base32（A–Z / 2–7）' };
    acc.label = (labelRaw || acc.label || '').trim();
    if (accounts.some(x => x.secret === acc.secret && x.label === acc.label)) {
      return { ok: false, msg: '该账号已存在' };
    }
    accounts.push(acc);
    saveBoard();
    return { ok: true, msg: '已添加「' + (acc.label || '未命名') + '」' };
  }

  $('btnAddOne').onclick = () => {
    const r = addOneAccount($('addSecret').value, $('addLabel').value);
    show($('boardMsg'), r.msg, !r.ok);
    if (r.ok) {
      $('addSecret').value = '';
      $('addLabel').value = '';
      renderBoard();
    }
  };

  function openEdit(i) {
    editIndex = i;
    const a = accounts[i];
    if (!a) return;
    $('editLabel').value = a.label || '';
    $('editSecret').value = a.secret || '';
    show($('editErr'), '');
    $('editMask').classList.remove('hidden');
    $('editSecret').focus();
  }

  function closeEdit() {
    editIndex = -1;
    $('editMask').classList.add('hidden');
  }

  $('btnEditCancel').onclick = closeEdit;
  $('btnQrClose').onclick = () => $('qrMask').classList.add('hidden');
  $('qrMask').onclick = (e) => { if (e.target === $('qrMask')) $('qrMask').classList.add('hidden'); };
  $('editMask').onclick = (e) => { if (e.target === $('editMask')) closeEdit(); };

  $('btnEditSave').onclick = () => {
    if (editIndex < 0 || editIndex >= accounts.length) return;
    const label = ($('editLabel').value || '').trim();
    const secretRaw = ($('editSecret').value || '').trim();
    const parsed = parseSecretInput(secretRaw);
    if (!parsed) {
      show($('editErr'), '密钥无效：请使用 Base32（A–Z / 2–7）', true);
      return;
    }
    accounts[editIndex] = { secret: parsed.secret, label: label || parsed.label || accounts[editIndex].label || '' };
    saveBoard();
    closeEdit();
    show($('boardMsg'), '已保存修改');
    renderBoard();
  };

  let boardRenderVersion = 0;
  let boardRefreshVersion = 0;
  async function refreshBoardCodes() {
    const version = boardRenderVersion;
    const refresh = ++boardRefreshVersion;
    const cards = Array.from($('grid').querySelectorAll('.acct'));
    const period = 30;
    const left = Math.max(1, period - (Math.floor(Date.now() / 1000) % period));
    await Promise.all(cards.map(async (card, i) => {
      const a = accounts[i];
      if (!a) return;
      const codeEl = card.querySelector('.code');
      try {
        const code = await totp(a.secret);
        if ((version !== boardRenderVersion || refresh !== boardRefreshVersion) || !card.isConnected || accounts[i] !== a) return;
        codeEl.dataset.code = code;
        codeEl.textContent = code.slice(0, 3) + ' ' + code.slice(3);
      } catch (e) {
        if ((version !== boardRenderVersion || refresh !== boardRefreshVersion) || !card.isConnected) return;
        delete codeEl.dataset.code;
        codeEl.textContent = '无效';
      }
      if (version === boardRenderVersion && refresh === boardRefreshVersion && card.isConnected) {
        card.querySelector('.t').textContent = left + 's';
        card.querySelector('i').style.width = (left / period * 100) + '%';
      }
    }));
  }

  async function renderBoard() {
    boardRenderVersion++;
    const grid = $('grid');
    grid.innerHTML = '';
    if (!accounts.length) {
      grid.innerHTML = '<div class="hint">还没有账号。用上方「添加账号」直接填名称和密钥即可。</div>';
      return;
    }
    for (let i = 0; i < accounts.length; i++) {
      const a = accounts[i];
      const idx = i;
      const card = document.createElement('div');
      card.className = 'acct';
      card.innerHTML =
        '<div class="name"></div>' +
        '<div class="code" title="点击复制">······</div>' +
        '<div class="meta"><span class="t"></span></div>' +
        '<div class="bar"><i></i></div>' +
        '<div class="actions">' +
          '<button type="button" class="sm btn-qr">二维码</button>' +
          '<button type="button" class="sm btn-edit">编辑</button>' +
          '<button type="button" class="sm danger btn-del">删除</button>' +
        '</div>';
      card.querySelector('.name').textContent = a.label || ('账号 ' + (idx + 1));
      card.querySelector('.btn-edit').onclick = (e) => { e.stopPropagation(); openEdit(idx); };
      card.querySelector('.btn-qr').onclick = (e) => {
        e.stopPropagation();
        const url = otpauthUrl(a);
        const data = makeQrDataUrl(url);
        if (!data) { show($('boardMsg'), '二维码生成失败', true); return; }
        $('qrTitle').textContent = (a.label || '账号') + ' · 二维码';
        $('qrDialogImg').src = data;
        $('qrOtpauth').textContent = url;
        $('qrMask').classList.remove('hidden');
      };
      card.querySelector('.btn-del').onclick = (e) => {
        e.stopPropagation();
        accounts.splice(idx, 1);
        saveBoard();
        renderBoard();
        show($('boardMsg'), '已删除');
      };
      const codeEl = card.querySelector('.code');
      codeEl.onclick = (e) => {
        e.stopPropagation();
        // Clipboard write must start in the user's click event, before any await.
        const code = codeEl.dataset.code;
        if (!code || !/^\d{6}$/.test(code)) {
          show($('boardMsg'), '验证码尚未生成，请稍后重试', true);
          return;
        }
        copyText(code).then(() => {
          show($('boardMsg'), '已复制 ' + (a.label || '验证码') + '（完整6位）');
        }).catch(() => {
          show($('boardMsg'), '复制失败，请检查浏览器剪贴板权限或使用 HTTPS', true);
        });
      };
      grid.appendChild(card);
    }
    refreshBoardCodes();
  }

  $('btnImport').onclick = () => {
    const lines = ($('bulk').value || '').split(/\r?\n/);
    let n = 0;
    for (const line of lines) {
      const acc = parseSecretInput(line);
      if (!acc) continue;
      if (accounts.some(x => x.secret === acc.secret && x.label === acc.label)) continue;
      accounts.push(acc); n++;
    }
    saveBoard();
    renderBoard();
    show($('boardMsg'), n ? ('已导入 ' + n + ' 个账号') : '没有识别到新账号', !n);
  };

  $('btnExport').onclick = async () => {
    const text = accounts.map(bookmarkUrl).join('\n');
    await copyText(text || '');
    show($('boardMsg'), accounts.length ? '已复制全部书签链接' : '看板为空', !accounts.length);
  };

  $('btnClear').onclick = () => {
    if (!accounts.length) { show($('boardMsg'), '看板已空'); return; }
    if (!confirm('确定清空全部账号？')) return;
    accounts = []; saveBoard(); renderBoard();
    show($('boardMsg'), '已清空');
  };

  (function loadHash() {
    const raw = (location.hash || '').replace(/^#/, '');
    if (!raw) return;
    const acc = parseSecretInput(raw.includes('secret=') ? raw : ('secret=' + raw));
    if (acc) {
      if (!acc.label) {
        const sp = new URLSearchParams(raw);
        acc.label = sp.get('label') || '';
      }
      setSingle(acc);
    }
  })();

  setInterval(() => {
    if (current && !panelSingle.classList.contains('hidden')) refreshSingle();
    if (!panelBoard.classList.contains('hidden')) refreshBoardCodes();
  }, 1000);
})();
