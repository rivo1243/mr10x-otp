const API = window.MR10X_API || 'https://mr10x-otp-production.up.railway.app';
let TOKEN = localStorage.getItem('mr10x_token');
let isRegister = false;
let pendingVerifyId = null;
let pendingFormData = null;
let resendCountdownTimer = null;
let isSubmitting = false;

function toast(msg, duration = 2500) {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.classList.add('show');
  setTimeout(() => el.classList.remove('show'), duration);
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;');
}

function selectPlan(val) {
  document.querySelectorAll('.plan-opt').forEach(opt => {
    const radio = opt.querySelector('input[type="radio"]');
    if (radio && radio.value === val) {
      opt.classList.add('selected');
      radio.checked = true;
    } else {
      opt.classList.remove('selected');
    }
  });
}

function getSelectedPlan() {
  const r = document.querySelector('.plan-opt input[type="radio"]:checked');
  return r ? r.value : 'plan1';
}

function toggleAuthMode() {
  isRegister = !isRegister;
  document.getElementById('auth-title').textContent = isRegister ? 'إنشاء حساب جديد' : 'تسجيل الدخول';
  document.getElementById('auth-sub').textContent = isRegister
    ? 'سجّل الآن واحصل على خدمة OTP لمتجرك'
    : 'مرحباً بك مجدداً — أدخل بياناتك للمتابعة';
  document.getElementById('submit-btn').textContent = isRegister ? 'إنشاء الحساب' : 'دخول';
  document.getElementById('toggle-text').textContent = isRegister ? 'لديك حساب بالفعل؟' : 'ليس لديك حساب؟';
  document.getElementById('toggle-link').textContent = isRegister ? 'سجّل دخولك' : 'سجّل الآن';
  document.getElementById('plan-selector').style.display = isRegister ? 'block' : 'none';
  document.getElementById('name-field').style.display = isRegister ? 'block' : 'none';
  document.getElementById('confirm-field').style.display = isRegister ? 'block' : 'none';
  document.getElementById('auth-err').style.display = 'none';
}

async function submitAuth() {
  if (isSubmitting) return;
  const errEl = document.getElementById('auth-err');
  errEl.style.display = 'none';

  const email = document.getElementById('email').value.trim();
  const password = document.getElementById('password').value;

  if (!email || !password) {
    errEl.textContent = 'يرجى إدخال البريد وكلمة المرور';
    errEl.style.display = 'block';
    return;
  }

  if (isRegister) {
    const name = document.getElementById('name').value.trim();
    const confirm = document.getElementById('confirm-password').value;
    const plan = getSelectedPlan();

    if (!name) { errEl.textContent = 'يرجى إدخال الاسم'; errEl.style.display = 'block'; return; }
    if (password !== confirm) { errEl.textContent = 'كلمتا المرور غير متطابقتين'; errEl.style.display = 'block'; return; }

    isSubmitting = true;
    document.getElementById('submit-btn').disabled = true;
    try {
      const r = await fetch(API + '/api/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, email, password, plan })
      });
      const data = await r.json();
      if (!r.ok) { errEl.textContent = data.error || 'فشل التسجيل'; errEl.style.display = 'block'; return; }

      pendingVerifyId = data.userId;
      pendingFormData = { email, password };
      document.getElementById('auth-body').style.display = 'none';
      document.getElementById('verify-box').style.display = 'block';
      document.getElementById('auth-form-content').style.display = 'none';
      document.getElementById('verify-email-label').textContent = email;
      setPendingWaLink();
      startResendCountdown(60);
    } finally {
      isSubmitting = false;
      document.getElementById('submit-btn').disabled = false;
    }

  } else {
    isSubmitting = true;
    document.getElementById('submit-btn').disabled = true;
    try {
      const r = await fetch(API + '/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });
      const data = await r.json();
      if (!r.ok) { errEl.textContent = data.error || 'بيانات خاطئة'; errEl.style.display = 'block'; return; }
      TOKEN = data.token;
      localStorage.setItem('mr10x_token', TOKEN);
      localStorage.setItem('mr10x_name', data.name || '');
      showDashboard(data.name);
      loadAll();
    } finally {
      isSubmitting = false;
      document.getElementById('submit-btn').disabled = false;
    }
  }
}

function setPendingWaLink() {
  const container = document.getElementById('wa-link-container');
  if (!container) return;
  const phone = '966580198626';
  const msg = encodeURIComponent('مرحباً، أحتاج مساعدة في تفعيل حسابي في MR10X');
  container.innerHTML = `<a class="wa-link" href="https://wa.me/${phone}?text=${msg}" target="_blank">📞 تواصل مع الدعم عبر واتساب</a>`;
}

async function confirmVerify() {
  const code = document.getElementById('verify-code').value.trim();
  const errEl = document.getElementById('verify-err');
  errEl.style.display = 'none';
  if (!code) { errEl.textContent = 'أدخل الرمز'; errEl.style.display = 'block'; return; }

  const r = await fetch(API + '/api/verify-email', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ userId: pendingVerifyId, code })
  });
  const data = await r.json();
  if (!r.ok) { errEl.textContent = data.error || 'رمز خاطئ'; errEl.style.display = 'block'; return; }

  TOKEN = data.token;
  localStorage.setItem('mr10x_token', TOKEN);
  localStorage.setItem('mr10x_name', data.name || '');
  if (resendCountdownTimer) clearInterval(resendCountdownTimer);
  showDashboard(data.name);
  loadAll();
}

function backToRegister() {
  document.getElementById('verify-box').style.display = 'none';
  document.getElementById('auth-body').style.display = 'block';
  document.getElementById('auth-form-content').style.display = 'block';
  if (resendCountdownTimer) clearInterval(resendCountdownTimer);
}

function startResendCountdown(seconds = 60) {
  const btn = document.getElementById('resend-btn');
  if (!btn) return;
  btn.disabled = true;
  btn.style.color = 'var(--accent2)';
  btn.style.borderColor = 'rgba(245,159,11,0.4)';
  let remaining = seconds;
  btn.textContent = `إعادة الإرسال بعد ${remaining}ث`;
  resendCountdownTimer = setInterval(() => {
    remaining--;
    if (remaining <= 0) {
      clearInterval(resendCountdownTimer);
      btn.disabled = false;
      btn.textContent = 'إعادة إرسال الرمز';
      btn.style.color = '';
      btn.style.borderColor = '';
    } else {
      btn.textContent = `إعادة الإرسال بعد ${remaining}ث`;
    }
  }, 1000);
}

async function resendCode() {
  if (!pendingVerifyId) return;
  const r = await fetch(API + '/api/resend-verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ userId: pendingVerifyId })
  });
  if (r.ok) {
    toast('تم إرسال الرمز مجدداً ✓');
    startResendCountdown(60);
  } else {
    const data = await r.json();
    toast(data.error || 'فشل الإرسال');
  }
}

function logout() {
  localStorage.removeItem('mr10x_token');
  localStorage.removeItem('mr10x_name');
  TOKEN = null;
  document.getElementById('dashboard-screen').style.display = 'none';
  document.getElementById('auth-screen').style.display = 'flex';
  document.getElementById('auth-body').style.display = 'block';
  document.getElementById('verify-box').style.display = 'none';
  document.getElementById('auth-form-content').style.display = 'block';
  document.getElementById('email').value = '';
  document.getElementById('password').value = '';
  document.getElementById('auth-err').style.display = 'none';
  if (isRegister) toggleAuthMode();
}

function showDashboard(name) {
  document.getElementById('auth-screen').style.display = 'none';
  document.getElementById('dashboard-screen').style.display = 'block';
  document.getElementById('topbar-username').textContent = name || 'بائع';
  const initials = (name || 'ب').charAt(0);
  document.getElementById('user-avatar-initials').textContent = initials;
}

function switchTab(name, el) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  el.classList.add('active');
  document.getElementById('panel-' + name).classList.add('active');
}

async function apiFetch(path, opts = {}) {
  return fetch(API + path, {
    ...opts,
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + TOKEN,
      ...(opts.headers || {})
    }
  });
}

async function loadAll() {
  await Promise.all([loadMailboxes(), loadSlots(), loadProfile()]);
}

const RENEWAL_WHATSAPP = '966580198626';

async function loadProfile() {
  const r = await apiFetch('/api/me');
  if (!r.ok) return;
  const me = await r.json();

  const days = me.subscription_days_left; // null = غير محدود، 0 = منتهي
  const numEl = document.getElementById('days-num');
  const dotEl = document.getElementById('sub-dot');
  const planEl = document.getElementById('plan-badge');

  if (days === null || days === undefined) {
    // اشتراك غير محدود
    numEl.textContent = 'غير محدود';
    numEl.className = '';
    dotEl.className = 'sub-dot';
  } else if (days > 7) {
    numEl.textContent = `${days} يوم متبقٍ`;
    numEl.className = '';
    dotEl.className = 'sub-dot';
  } else if (days > 0) {
    numEl.textContent = `${days} يوم متبقٍ`;
    numEl.className = 'warning';
    dotEl.className = 'sub-dot warning';
  } else {
    numEl.textContent = 'منتهي الصلاحية';
    numEl.className = 'expired';
    dotEl.className = 'sub-dot expired';
  }

  const planNames = { plan1: 'أساسية', plan2: 'احترافية', plan3: 'متقدمة' };
  planEl.textContent = planNames[me.plan] || me.plan || '';

  const msg = encodeURIComponent(`مرحباً، أريد تجديد اشتراكي في MR10X - ${me.name || ''}`);
  document.getElementById('renew-wa-link').href = `https://wa.me/${RENEWAL_WHATSAPP}?text=${msg}`;
}

let mailboxCache = [];

async function loadMailboxes() {
  const r = await apiFetch('/api/mailboxes');
  if (!r.ok) return;
  const list = await r.json();
  mailboxCache = list;

  const countEl = document.getElementById('mailboxes-count');
  countEl.textContent = list.length ? `${list.length} صندوق` : '';

  const container = document.getElementById('mailboxes-list');
  if (!list.length) {
    container.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">📭</div>
        <div class="empty-title">لا توجد صناديق بريد</div>
        <div class="empty-sub">أضف صندوق بريد لبدء استقبال رموز OTP</div>
      </div>`;
    return;
  }

  container.innerHTML = list.map(mb => {
    const isConnected = !!mb.gmail_connected;
    const badge = isConnected
      ? `<span class="badge badge-green">Gmail متصل</span>`
      : `<span class="badge badge-muted">غير متصل</span>`;
    const connectBtn = isConnected
      ? `<button class="btn-sm danger" data-action="disconnect-gmail" data-id="${mb.id}">قطع الاتصال</button>`
      : `<button class="btn-sm accent" data-action="connect-gmail" data-id="${mb.id}">ربط Gmail</button>`;
    return `
      <div class="card">
        <div class="card-row">
          <div class="card-left">
            <div class="card-icon">📧</div>
            <div class="card-info">
              <div class="card-name">${escapeHtml(mb.label || mb.email)}</div>
              <div class="card-meta">${escapeHtml(mb.email)}</div>
            </div>
          </div>
          <div class="card-actions">
            ${badge}
            ${connectBtn}
            <button class="btn-sm danger" data-action="delete-mailbox" data-id="${mb.id}">حذف</button>
          </div>
        </div>
      </div>`;
  }).join('');
}

async function connectGmail(mailboxId) {
  try {
    const r = await apiFetch('/api/auth/gmail/start?mailbox_id=' + mailboxId);
    if (!r.ok) {
      if (r.status === 503) {
        toast('خدمة Gmail غير مفعّلة — تواصل مع الدعم');
      } else if (r.status === 403) {
        toast('تحقق من صلاحية اشتراكك أولاً');
      } else {
        toast('فشل بدء ربط Gmail (' + r.status + ')');
      }
      return;
    }
    const data = await r.json();
    if (data.url) window.location.href = data.url;
  } catch (err) {
    toast('خطأ في الاتصال بالخادم');
  }
}

async function disconnectGmail(mailboxId) {
  const r = await apiFetch('/api/mailboxes/' + mailboxId + '/gmail-disconnect', { method: 'POST' });
  if (r.ok) { toast('تم قطع الاتصال'); loadMailboxes(); }
  else toast('فشل قطع الاتصال');
}

async function loadSlots() {
  const r = await apiFetch('/api/slots');
  if (!r.ok) return;
  const list = await r.json();

  const countEl = document.getElementById('slots-count');
  countEl.textContent = list.length ? `${list.length} رابط` : '';

  const container = document.getElementById('slots-list');
  if (!list.length) {
    container.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">🔗</div>
        <div class="empty-title">لا توجد روابط</div>
        <div class="empty-sub">أضف رابطاً لزبون لبدء إرسال الرموز</div>
      </div>`;
    return;
  }

  container.innerHTML = list.map(sl => {
    const slotUrl = sl.url || (window.location.origin + '/code.html?t=' + sl.token);
    const editBtn = `<button class="btn-sm" style="border-color:rgba(245,159,11,0.3);color:var(--accent);"
      data-action="edit-slot" data-id="${sl.id}" data-email="${escapeHtml(sl.account_email||'')}">تعديل</button>`;
    return `
      <div class="card">
        <div class="card-row">
          <div class="card-left">
            <div class="card-icon">🔗</div>
            <div class="card-info">
              <div class="card-name">${escapeHtml(sl.label || 'رابط')}</div>
              <div class="card-meta">${escapeHtml(sl.account_email || '')}</div>
            </div>
          </div>
          <div class="card-actions">
            ${editBtn}
            <button class="btn-sm" data-action="copy-link" data-url="${escapeHtml(slotUrl)}">نسخ الرابط</button>
            <button class="btn-sm danger" data-action="delete-slot" data-id="${sl.id}">حذف</button>
          </div>
        </div>
        <div class="webhook-row">
          <div class="webhook-url">${escapeHtml(slotUrl)}</div>
          <button class="btn-sm" data-action="copy-webhook" data-url="${escapeHtml(slotUrl)}">نسخ</button>
        </div>
      </div>`;
  }).join('');
}

function copyLink(url) {
  navigator.clipboard.writeText(url).then(() => toast('تم نسخ الرابط ✓'));
}

function openModal(id) { document.getElementById(id).classList.add('open'); }
function closeModal(id) { document.getElementById(id).classList.remove('open'); }

function openAddMailbox() {
  document.getElementById('mb-email').value = '';
  document.getElementById('mb-label').value = '';
  document.getElementById('mb-err').style.display = 'none';
  document.getElementById('mb-ok').style.display = 'none';
  openModal('add-mailbox-modal');
}

// Handle URL params on load
document.addEventListener('DOMContentLoaded', () => {
  const params = new URLSearchParams(window.location.search);
  if (params.get('register') === '1') {
    if (!isRegister) toggleAuthMode();
  }
  if (params.get('gmail_connected') === '1') {
    toast('تم ربط Gmail بنجاح ✓');
    window.history.replaceState({}, '', window.location.pathname);
  }
  if (params.get('gmail_error')) {
    toast('فشل ربط Gmail: ' + params.get('gmail_error'));
    window.history.replaceState({}, '', window.location.pathname);
  }

  // ── Event delegation for mailbox buttons ──
  const mailboxList = document.getElementById('mailboxes-list');
  if (mailboxList) {
    mailboxList.addEventListener('click', e => {
      const btn = e.target.closest('[data-action]');
      if (!btn) return;
      const { action, id } = btn.dataset;
      if (action === 'connect-gmail')    connectGmail(Number(id));
      if (action === 'disconnect-gmail') disconnectGmail(Number(id));
      if (action === 'delete-mailbox')   deleteMailbox(Number(id));
    });
  }

  // ── Event delegation for slot buttons ──
  const slotsList = document.getElementById('slots-list');
  if (slotsList) {
    slotsList.addEventListener('click', e => {
      const btn = e.target.closest('[data-action]');
      if (!btn) return;
      const { action, id, url, email } = btn.dataset;
      if (action === 'edit-slot')    openEditSlot(Number(id), email || '', '');
      if (action === 'copy-link')    copyLink(url);
      if (action === 'copy-webhook') copyWebhook(url);
      if (action === 'delete-slot')  deleteSlot(Number(id));
    });
  }
});

async function addMailbox() {
  const email = document.getElementById('mb-email').value.trim();
  const label = document.getElementById('mb-label').value.trim();
  const errEl = document.getElementById('mb-err');
  const okEl = document.getElementById('mb-ok');
  errEl.style.display = 'none';
  okEl.style.display = 'none';

  if (!email) { errEl.textContent = 'البريد مطلوب'; errEl.style.display = 'block'; return; }

  try {
    const r = await apiFetch('/api/mailboxes', {
      method: 'POST',
      body: JSON.stringify({ email, label })
    });
    const data = await r.json();
    if (!r.ok) { errEl.textContent = data.error || 'فشل الإضافة'; errEl.style.display = 'block'; return; }
    okEl.style.display = 'block';
    setTimeout(() => { closeModal('add-mailbox-modal'); loadMailboxes(); }, 1200);
  } catch(e) {
    errEl.textContent = 'تعذر الاتصال بالسيرفر';
    errEl.style.display = 'block';
  }
}

async function deleteMailbox(id) {
  const r = await apiFetch('/api/mailboxes/' + id, { method: 'DELETE' });
  if (r.ok) {
    toast('تم حذف الصندوق ✓');
  } else {
    toast('فشل الحذف — حاول مرة أخرى');
  }
  loadAll();
}

function copyWebhook(url) {
  navigator.clipboard.writeText(url).then(() => toast('تم نسخ رابط الـ Webhook ✓'));
}

function autoFillSlotEmail() {
  const sel = document.getElementById('slot-mailbox');
  const emailInput = document.getElementById('slot-account-email');
  if (!sel || !emailInput) return;
  const chosen = mailboxCache.find(m => m.id === sel.value);
  if (chosen) emailInput.value = String(chosen.email || '');
}

function openAddSlot() {
  if (!mailboxCache.length) { toast('أضف صندوق إيميل أولاً'); return; }
  const sel = document.getElementById('slot-mailbox');
  sel.innerHTML = mailboxCache.map(m => `<option value="${m.id}">${escapeHtml(m.email)}</option>`).join('');
  document.getElementById('slot-label').value = '';
  document.getElementById('slot-account-pass').value = '';
  document.getElementById('slot-count').value = '1';
  document.getElementById('slot-err').style.display = 'none';
  autoFillSlotEmail();
  openModal('add-slot-modal');
}

async function addSlot() {
  const mailbox_id = document.getElementById('slot-mailbox').value;
  const label = document.getElementById('slot-label').value.trim();
  const account_email = document.getElementById('slot-account-email').value.trim();
  const account_password = document.getElementById('slot-account-pass').value;
  const count = document.getElementById('slot-count').value;
  const errEl = document.getElementById('slot-err');
  errEl.style.display = 'none';

  if (!label) { errEl.textContent = 'اسم الزبون مطلوب'; errEl.style.display = 'block'; return; }

  const r = await apiFetch('/api/slots', {
    method: 'POST',
    body: JSON.stringify({ mailbox_id, label, count: Number(count), account_email, account_password })
  });
  const data = await r.json();
  if (!r.ok) { errEl.textContent = data.error; errEl.style.display = 'block'; return; }
  closeModal('add-slot-modal');
  switchTab('slots', document.querySelectorAll('.tab')[1]);
  loadSlots();
  toast(`تم إنشاء ${data.length} رابط ✓`);
}

function openEditSlot(id, email, pass) {
  document.getElementById('edit-slot-id').value = id;
  document.getElementById('edit-account-email').value = email || '';
  document.getElementById('edit-account-pass').value = pass || '';
  document.getElementById('edit-slot-err').style.display = 'none';
  openModal('edit-slot-modal');
}

async function saveSlotEdit() {
  const id = document.getElementById('edit-slot-id').value;
  const account_email = document.getElementById('edit-account-email').value.trim();
  const account_password = document.getElementById('edit-account-pass').value;
  const errEl = document.getElementById('edit-slot-err');
  errEl.style.display = 'none';

  const r = await apiFetch('/api/slots/' + id, {
    method: 'PATCH',
    body: JSON.stringify({ account_email, account_password })
  });
  if (!r.ok) { errEl.textContent = 'فشل الحفظ'; errEl.style.display = 'block'; return; }
  closeModal('edit-slot-modal');
  loadSlots();
  toast('تم حفظ البيانات ✓');
}

async function deleteSlot(id) {
  await apiFetch('/api/slots/' + id, { method: 'DELETE' });
  loadSlots();
}

// ── Init ──
if (TOKEN) {
  apiFetch('/api/me').then(async r => {
    if (r.ok) {
      const me = await r.json();
      localStorage.setItem('mr10x_name', me.name || '');
      showDashboard(me.name);
      loadAll();
    } else {
      localStorage.removeItem('mr10x_token');
      localStorage.removeItem('mr10x_name');
      TOKEN = null;
    }
  }).catch(() => {});
}

document.addEventListener('keydown', e => {
  if (e.key === 'Enter') {
    const _vb = document.getElementById('verify-box'); const verifyBoxVisible = _vb && _vb.style.display !== 'none';
    if (verifyBoxVisible) return;
    if (document.getElementById('auth-screen').style.display !== 'none') submitAuth();
  }
  if (e.key === 'Escape') {
    document.querySelectorAll('.modal-overlay.open').forEach(m => m.classList.remove('open'));
  }
});
