# Security Considerations & Guarantees — `mixudev/security-defense`

Dokumen ini mendefinisikan batasan keamanan data, strategi privasi, dan perlindungan terhadap kebocoran kredensial dalam package.

---

## 1. Perlindungan Kredensial Sensitif (Zero-Leakage Policy)

Package keamanan tidak boleh menjadi sumber kebocoran data (*security liability*).

### Larangan Keras
Dilarang menyimpan atau mentransmisikan data berikut dalam log, alert database, atau channel third-party:
- Plaintext Password
- Password Confirmation
- Session ID / Session Cookies
- Access Token (Bearer token, OAuth token, Sanctum/Passport PAT)
- API Keys & Client Secrets
- Two-Factor / OTP Plain Codes
- Telegram Bot Token / Webhook Secrets

### Mekanisme Proteksi Otomatis
1. **Sanitizer Pipeline**: Setiap input metadata yang masuk ke `SecurityEvent` wajib melewati `Sanitizer::clean($metadata)`.
2. Key-key sensitif (`password`, `secret`, `token`, `authorization`, dll) digantikan dengan string `[REDACTED]`.
3. Input bertingkat (nested array) disanitasi secara rekursif.

---

## 2. Keamanan Alert Delivery (Channels)

1. **Telegram & Discord Integrasi**:
   - Token/URL webhook tidak boleh di-echo ke log saat terjadi error.
   - Pesan yang dikirim hanya memuat ringkasan metadata yang telah tersanitasi.
   - Panggilan HTTP menggunakan HTTPS dan timeout yang wajar (default 3-5 detik) agar tidak memblokir antrean request.

2. **Database Persistence**:
   - Kolom `metadata` disimpan dalam format JSON.
   - Foreign key atau data relasional tidak mengunci tabel auth host application.

---

## 3. Resilience Terhadap DoS & Alert Flooding

1. **Sliding-Window Deduplication**:
   - Mencegah spam ribuan alert dari serangan brute force berkecepatan tinggi.
   - Fingerprint unik membatasi alert baru dalam jendela waktu tertentu (default 300 detik).
2. **Fail-Safe Processing**:
   - Jika Telegram atau Discord gagal merespons, exception ditangkap secara internal (logged as warning), dan proses aplikasi utama tidak crash.
