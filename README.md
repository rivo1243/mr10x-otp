# Mr10x OTP System

نظام توصيل أكواد التحقق تلقائياً من البريد الإلكتروني إلى الزبائن.

## كيف يعمل

1. المتجر يربط صندوق إيميله بالنظام عبر IMAP
2. النظام يراقب الإيميلات ويستخرج أكواد OTP تلقائياً كل 15 ثانية
3. المتجر ينشئ روابط خاصة لكل زبون
4. الزبون يفتح الرابط ويرى الكود فوراً — ينتهي بعد 10 دقائق

---

## تشغيل محلي

### المتطلبات
- Node.js 18+

### الخطوات

```bash
cd backend
npm install
cp .env.example .env
# عدّل .env وأضف SECRET عشوائي
node src/server.js
```

الواجهة: افتح `frontend/index.html` في المتصفح.

أو استخدم serve:
```bash
npx serve frontend -p 3000
```

> تأكد من تعيين `window.MR10X_API` أو أن الباكند يعمل على `http://localhost:4000`

---

## البنية

```
mr10x-otp/
├── backend/
│   ├── src/
│   │   ├── server.js     # Express API
│   │   ├── db.js         # SQLite schema
│   │   ├── imap.js       # IMAP connection
│   │   ├── extract.js    # OTP regex extractor
│   │   └── poller.js     # Background polling
│   ├── .env.example
│   └── package.json
└── frontend/
    ├── index.html        # لوحة تحكم المتجر
    └── code.html         # صفحة الزبون
```

## API

| الطريقة | المسار | الوصف |
|---------|--------|-------|
| POST | `/api/register` | إنشاء حساب |
| POST | `/api/login` | تسجيل دخول |
| GET | `/api/mailboxes` | قائمة صناديق البريد |
| POST | `/api/mailboxes` | ربط صندوق جديد |
| DELETE | `/api/mailboxes/:id` | حذف صندوق |
| GET | `/api/slots` | قائمة روابط الزبائن |
| POST | `/api/slots` | إنشاء روابط |
| DELETE | `/api/slots/:id` | حذف رابط |
| GET | `/api/code/:token` | **عام** — جلب الكود للزبون |

---

Built with ❤️ — Mr10x
