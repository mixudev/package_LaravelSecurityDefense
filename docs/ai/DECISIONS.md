# Architecture Decision Records (ADR) — `mixudev/security-defense`

Dokumen ini mencatat seluruh keputusan arsitektural penting beserta konteks, alternatif, dan alasannya.

---

## ADR-001: Decoupling dari Authentication Packages

### Status
Accepted

### Context
Aplikasi Laravel menggunakan berbagai sistem autentikasi (Laravel Fortify, Breeze, Sanctum, Jetstream, Sentinel, custom JWT, dll). Jika package ini terikat langsung ke namespace salah satu package auth, reusability package akan hilang.

### Decision
Membuat abstraksi generic `ThreatSource` dan DTO `SecurityEvent`. Package tidak mengimpor namespace package autentikasi mana pun. Event autentikasi apa pun dapat di-bridge via Adapter atau listener generik.

### Alternatives Considered
- Direct listener terhadap `Illuminate\Auth\Events\Failed` dan event sejenis.

### Why Rejected
Membatasi fleksibilitas untuk sistem auth berbasis API kustom, event custom (seperti `OTP_FAILED`, `ACCOUNT_LOCKED`), atau integrasi non-standard. Adapter pola memungkinkan integrasi tanpa coupling.

---

## ADR-002: Cache-Backed Sliding Window untuk Stateful Rules

### Status
Accepted

### Context
Deteksi serangan seperti Brute Force, Credential Stuffing, dan Distributed Spray membutuhkan tracking frekuensi kejadian dalam kurun waktu tertentu (time window).

### Decision
Menggunakan driver `Illuminate\Contracts\Cache\Repository` (Laravel Cache) untuk menyimpan data frekuensi/timestamp berdasarkan hashing key identitas (IP, identifier, pattern).

### Alternatives Considered
- Menyimpan setiap raw telemetry event ke database SQL secara permanen.
- In-memory PHP array (stateless per request).

### Why Rejected
- Menyimpan semua raw attempt ke SQL tabel menyebabkan I/O bottleneck tinggi saat diserang volume besar.
- In-memory PHP array hilang begitu request berakhir (tidak bisa mendeteksi serangan multi-request).
- Cache backend (Redis/Memcached/DB) sangat cepat, mendukung TTL otomatis, dan kompatibel dengan multi-server/load-balanced environments.

---

## ADR-003: Mandatory Data Sanitization & Redaction Layer

### Status
Accepted

### Context
Telemetry keamanan sering kali menyertakan metadata dari request (seperti parameter form, headers, payload json). Jika tidak disaring, data sensitif (password, secret token, credit card) dapat bocor ke database alert, log, atau channel third-party seperti Telegram/Discord.

### Decision
Mengimplementasikan kelas `Sanitizer` yang secara rekursif melakukan masking/redaction terhadap key-key sensitif (`password`, `token`, `secret`, `authorization`, `cookie`, dll) sebelum metadata dimasukkan ke `SecurityEvent` atau disimpan ke database/channel.

### Alternatives Considered
- Mengandalkan user/developer untuk membersihkan data sendiri sebelum memanggil package.

### Why Rejected
Human error tinggi. Keamanan package harus memiliki prinsip *Defense in Depth* dan *Secure by Default*.

---

## ADR-004: Deduplikasi Alert Menggunakan Fingerprint + Time Window

### Status
Accepted

### Context
Ketika terjadi serangan brute force terus menerus dengan ribuan request per detik, sistem notifikasi (Telegram, Discord, Webhook) bisa terkena rate-limit atau membanjiri tim engineering (alert fatigue).

### Decision
Menghitung `fingerprint` unik (`sha256(threatType + target/ip + context)`) dan memeriksa cache deduplikasi sebelum alert baru dikirim atau disimpan ulang. Jika masih dalam window, notifikasi ditekan (suppressed) atau di-aggregate.

---

## ADR-005: Fail-Safe Notification Channels

### Status
Accepted

### Context
Koneksi ke Telegram Bot API atau Discord Webhook sewaktu-waktu dapat mengalami timeout, rate-limited, atau belum dikonfigurasi di environment tertentu (staging/testing).

### Decision
`DatabaseChannel` adalah channel wajib utama. Channel pihak ketiga (`TelegramChannel`, `DiscordChannel`, `WebhookChannel`) dibungkus dalam try-catch gracefully. Jika tidak dikonfigurasi atau gagal terhubung, alert tetap tersimpan di database dan kegagalan dicatat ke logger tanpa melempar fatal exception yang mengganggu request pengguna.
