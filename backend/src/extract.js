// استخراج كود التحقق OTP من نص الإيميل
const PATTERNS = [
  // أرقام بجانب كلمات تحقق
  /(?:verification|confirm|activate|otp|code|كود|رمز|تحقق|تفعيل)[^\d]{0,30}(\d{4,8})/i,
  /(\d{4,8})[^\d]{0,30}(?:is your|هو|كودك|رمزك|verification|code)/i,
  // الكود في سطر منفصل أو بين فراغات
  /^\s*(\d{4,8})\s*$/m,
  // G- أو كود مع شرطة
  /\bG-(\d{6})\b/,
  // كود كبير وحده
  /\b([A-Z0-9]{6,8})\b/,
];

export function extractCode(subject = '', body = '') {
  const text = `${subject}\n${body}`;
  for (const pattern of PATTERNS) {
    const m = text.match(pattern);
    if (m) {
      const code = m[1] || m[0];
      if (/^\d{4,8}$/.test(code) || /^[A-Z0-9]{6,8}$/.test(code)) {
        return code.trim();
      }
    }
  }
  return null;
}
