// ── استخراج كود OTP من عنوان + نص الإيميل ────────────────────────────────
// يغطّي: Google, Apple, Microsoft, Netflix, WhatsApp, Snapchat, Instagram,
//         Facebook, Twitter/X, Amazon, Spotify, Steam, OSN, Shahid, STC Play,
//         وغيرها — عربي وإنجليزي

// ── كلمات مفتاحية ─────────────────────────────────────────────────────────
const KW_EN = [
  'verification', 'verify', 'confirm', 'confirmation', 'activate', 'activation',
  'otp', 'one.?time', 'passcode', 'access', 'login', 'sign.?in', 'sign.?up',
  'security', 'auth(?:entication)?', 'password', 'reset', 'temporary', 'temp',
  'single.?use', 'access', 'entry', 'unlock'
].join('|');

const KW_AR = [
  'رمز', 'كود', 'رقم', 'كلمة المرور', 'تحقق', 'تفعيل', 'تأكيد',
  'دخول', 'مؤقت', 'سري', 'أمان', 'الاشتراك', 'التحقق', 'التفعيل'
].join('|');

const NOUN_EN = '(?:code|pin|otp|token|key|number|password|pass)?';
const IS_EN   = '(?:is|was|:)?';
const IS_AR   = '(?:هو|هي|:)?';

const PATTERNS = [
  // ── 1. Google: G-XXXXXX ──────────────────────────────────────────────────
  /\bG-(\d{6})\b/,

  // ── 2. WhatsApp / Telegram: XXX-XXX ─────────────────────────────────────
  /\b(\d{3})[-\s](\d{3})\b/,         // يُعالَج لاحقاً لدمج المجموعتين

  // ── 3. كلمة مفتاحية إنجليزية → كود ──────────────────────────────────────
  new RegExp(
    `(?:${KW_EN})\\s*${NOUN_EN}\\s*${IS_EN}\\s*([A-Z0-9]{4,8})`,
    'i'
  ),

  // ── 4. كود → كلمة مفتاحية إنجليزية ──────────────────────────────────────
  new RegExp(
    `([A-Z0-9]{4,8})\\s+${IS_EN}\\s*your\\s*(?:${KW_EN})?\\s*${NOUN_EN}`,
    'i'
  ),

  // ── 5. كلمة مفتاحية عربية → كود ─────────────────────────────────────────
  new RegExp(
    `(?:${KW_AR})\\s*${IS_AR}\\s*(\\d{4,8})`
  ),

  // ── 6. كود → كلمة مفتاحية عربية ─────────────────────────────────────────
  new RegExp(
    `(\\d{4,8})\\s*(?:${IS_AR})\\s*(?:${KW_AR})`
  ),

  // ── 7. بعد نقطتين مباشرةً (subject/body): "code: 847291" ────────────────
  /:\s*([A-Z0-9]{4,8})\b/i,

  // ── 8. سطر منفصل — أرقام فقط 4-8 ─────────────────────────────────────────
  /^\s*(\d{4,8})\s*$/m,

  // ── 9. سطر منفصل — أحرف كبيرة + أرقام 6-8 ────────────────────────────────
  /^\s*([A-Z0-9]{6,8})\s*$/m,

  // ── 10. "is XXXXX" / "= XXXXX" (Apple, Microsoft, Steam) ────────────────
  /(?:is|=)\s+([A-Z0-9]{4,8})\b/i,

  // ── 11. الكود بين علامتي تنصيص أو أقواس ────────────────────────────────
  /["'«»【】\[\]()]\s*([A-Z0-9]{4,8})\s*["'«»【】\[\]()]/i,

  // ── 12. رقم كبير وحده في العنوان (Subject) ──────────────────────────────
  // (يُطبَّق على subject فقط — انظر extractCode)
  null, // placeholder — يُعالَج يدوياً

  // ── 13. fallback: أي 6-8 أرقام متتالية منفصلة ──────────────────────────
  /\b(\d{6,8})\b/,
];

// ── فحص صحة الكود ─────────────────────────────────────────────────────────
function isValidCode(code) {
  if (!code) return false;
  const c = code.replace(/[-\s]/g, '');      // ازل شرطات WhatsApp
  return /^\d{4,8}$/.test(c) || /^[A-Z0-9]{6,8}$/.test(c);
}

// ── تطبيع الكود ───────────────────────────────────────────────────────────
function normalizeCode(code) {
  return code.replace(/[-\s]/g, '').trim().toUpperCase();
}

// ── تصفية كلمات / نصوص شائعة تُشبه الأكواد لكنها ليست أكواد ─────────────
const BLACKLIST = new Set([
  'HTTP', 'HTTPS', 'HTML', 'FROM', 'REPLY', 'EMAIL', 'USER', 'NAME',
  'DATE', 'MIME', 'PART', 'TEXT', 'TYPE', 'BODY', 'HELP', 'INFO',
  'CLICK', 'LINK', 'VIEW', 'READ', 'OPEN', 'MORE', 'NEXT', 'BACK',
  'SAFE', 'SECURE', 'SIGN', 'TRUE', 'NULL', 'NONE', 'FREE', 'BEST',
]);

function isBlacklisted(code) {
  return BLACKLIST.has(code.toUpperCase());
}

// ── الدالة الرئيسية ────────────────────────────────────────────────────────
export function extractCode(subject = '', body = '') {
  const subjectClean = subject.trim();
  const fullText     = `${subjectClean}\n${body}`;

  // محاولة 1: G-XXXXXX
  {
    const m = fullText.match(/\bG-(\d{6})\b/);
    if (m) return m[1];
  }

  // محاولة 2: WhatsApp XXX-XXX
  {
    const m = fullText.match(/\b(\d{3})[-\s](\d{3})\b/);
    if (m) {
      const code = m[1] + m[2];
      if (isValidCode(code)) return code;
    }
  }

  // محاولة 3: subject فقط — لو هو عبارة عن رقم وحده
  {
    const m = subjectClean.match(/^[^\d]*(\d{4,8})[^\d]*$/);
    if (m && isValidCode(m[1])) return m[1];
  }

  // محاولة 4-11: بقية الأنماط على النص الكامل
  const patternsToTry = PATTERNS.slice(2).filter(Boolean);
  for (const pattern of patternsToTry) {
    const m = fullText.match(pattern);
    if (!m) continue;

    const raw = m[1] || m[0];
    if (!raw) continue;

    const code = normalizeCode(raw);
    if (isValidCode(code) && !isBlacklisted(code)) {
      return code;
    }
  }

  return null;
}
