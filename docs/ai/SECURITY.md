# Security Considerations & Guarantees — `mixudev/security-defense`

Dokumen ini mendefinisikan batasan keamanan, strategi privasi, dan mekanisme *self-defense* yang menjamin package ini tidak menjadi celah atau liabilitas baru (*zero vulnerability guarantee*).

---

## 1. Perlindungan Kredensial Sensitif (Zero-Leakage Policy)

Package keamanan tidak boleh menjadi sumber kebocoran data (*security liability*).

### Larangan Keras
Dilarang menyimpan atau mentransmisikan data berikut dalam log, alert database, atau channel third-party:
- Plaintext Password / Password Confirmation
- Session ID / Session Cookies
- Access Token (Bearer token, OAuth token, Sanctum/Passport PAT)
- API Keys & Client Secrets
- Two-Factor / OTP Plain Codes
- Telegram Bot Token / Webhook Secrets

### Mekanisme Proteksi Otomatis
1. **Sanitizer Pipeline**: Setiap input metadata yang masuk ke `SecurityEvent` wajib melewati `Sanitizer::clean($metadata)`.
2. Key-key sensitif (`password`, `secret`, `token`, `authorization`, `cookie`, `credit_card`, dll) digantikan dengan string `[REDACTED]`.
3. Input bertingkat (nested array) disanitasi secara rekursif hingga batas `max_traversal_depth`.

---

## 2. Self-Defense & Mitigasi Denial-of-Service (Anti-ReDoS & Memory Bounding)

WAF dan security scanner kerap menjadi sasaran penyerang untuk melumpuhkan server korban melalui teknik resource exhaustion:

| Vektor Eksploitasi | Risiko | Solusi Built-in Package |
|---|---|---|
| **ReDoS (Regex DoS)** | Mengirim string acak 5MB berpola khusus untuk mengunci CPU server pada *catastrophic backtracking*. | `hardening.max_inspection_length` (default 4096 chars). Payload dipotong aman sebelum diinspeksi regex. |
| **Stack Overflow / Memory Exhaustion** | Mengirim JSON bertingkat ratusan layer untuk menyebabkan rekursi tanpa henti (*OOM Crash*). | `hardening.max_traversal_depth` (default 5). Rekursi dihentikan otomatis saat mencapai batas kedalaman. |
| **Alert Disk Flooding** | Menyerang aplikasi secara masif untuk memenuhi kapasitas disk database dengan jutaan record alert. | `hardening.alert_rate_limit` (default max 60 alerts/menit ke database) + `AlertDeduplicator` fingerprint. |
| **CPU Saturation Saat Serangan Masif** | Mengirim ribuan request per detik agar server terus-menerus mengeksekusi puluhan regex WAF. | `IpQuarantineService` (Fail2Ban auto-jail). Begitu terbukti menyerang, IP di-quarantine; request berikutnya ditolak instan di baris pertama middleware (HTTP 429). |

---

## 3. Whitelist & Pencegahan Lockout Sendiri (Self-Lockout Prevention)

Fitur IP Quarantine dilengkapi dengan daftar putih (`middleware.quarantine.whitelist`) default:
- `127.0.0.1`
- `::1`
- Developer atau upstream load balancer terpercaya dapat ditambahkan ke whitelist agar tidak pernah terisolasi secara tidak sengaja.

---

## 4. Keamanan Integrasi & Anti-Timing Attack

1. **Webhook Signature Verification**:
   - Header `X-Security-Defense-Signature` dihasilkan dengan `hash_hmac('sha256', ...)`.
   - Verifikasi wajib menggunakan `hash_equals()` untuk mencegah eksploitasi timing-attack side channel.

2. **Asynchronous Isolation**:
   - Kegagalan koneksi pihak ketiga (Telegram/Discord/SIEM) tidak pernah menghentikan alur request aplikasi pengguna.
   - Pilihan queue background memastikan response time HTTP tetap konstan tanpa beban I/O jaringan eksternal.
