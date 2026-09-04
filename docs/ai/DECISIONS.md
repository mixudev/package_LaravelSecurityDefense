# Architecture Decision Records (ADR) — `mixudev/security-defense`

Dokumen ini mencatat seluruh keputusan arsitektural penting beserta konteks, alternatif, dan alasannya.

---

## ADR-001: Decoupling dari Authentication Packages

### Status: Accepted
Membuat abstraksi generic `ThreatSource` dan DTO `SecurityEvent`. Package tidak mengimpor namespace package autentikasi mana pun. Event autentikasi apa pun dapat di-bridge via Adapter atau listener generik.

---

## ADR-002: Cache-Backed Sliding Window untuk Stateful Rules

### Status: Accepted
Menggunakan driver `Illuminate\Contracts\Cache\Repository` (Laravel Cache) untuk menyimpan data frekuensi/timestamp berdasarkan hashing key identitas (IP, identifier, pattern).

---

## ADR-003: Mandatory Data Sanitization & Redaction Layer

### Status: Accepted
Mengimplementasikan kelas `Sanitizer` yang secara rekursif melakukan masking/redaction terhadap key-key sensitif (`password`, `token`, `secret`, `authorization`, `cookie`, dll) sebelum metadata dimasukkan ke `SecurityEvent` atau disimpan ke database/channel.

---

## ADR-004: Deduplikasi Alert Menggunakan Fingerprint + Time Window

### Status: Accepted
Menghitung `fingerprint` unik (`sha256(threatType + target/ip + context)`) dan memeriksa cache deduplikasi sebelum alert baru dikirim atau disimpan ulang.

---

## ADR-005: Fail-Safe Notification Channels

### Status: Accepted
`DatabaseChannel` adalah channel wajib utama. Channel pihak ketiga (`TelegramChannel`, `DiscordChannel`, `WebhookChannel`) dibungkus dalam try-catch gracefully. Jika gagal terhubung atau unconfigured, alert tetap tersimpan di database dan kegagalan dicatat ke logger tanpa melempar fatal exception.

---

## ADR-006: Anti-ReDoS & Memory Hardening Bounds (Zero Vulnerability Guarantee)

### Status: Accepted
### Context
Scanner WAF dan sanitasi metadata rentan menjadi target DoS jika attacker mengirim payload string sangat besar (misal string 10MB berulang) yang memicu *catastrophic backtracking* pada regex (ReDoS) atau kehabisan RAM/stack recursion.
### Decision
Menerapkan batas inspeksi panjang karakter (`hardening.max_inspection_length`, default 4096) sebelum evaluasi regex, serta batas kedalaman rekursi (`hardening.max_traversal_depth`, default 5) pada `Sanitizer`.
### Trade-off
Payload setelah 4KB dipotong aman (*truncated*), namun 99.9% serangan injeksi dieksekusi pada 100-500 karakter pertama. Keuntungan keamanan server jauh lebih besar.

---

## ADR-007: Active IP Quarantine & Auto-Jail (Fail2Ban-Style Defense)

### Status: Accepted
### Context
Ketika diserang secara intensif oleh bot, server dapat kewalahan jika harus mengeksekusi puluhan regex WAF dan query database untuk setiap request berbahaya.
### Decision
Menerapkan `IpQuarantineService`. IP yang terbukti melakukan serangan injeksi kritis atau mengumpulkan skor ancaman di atas batas threshold otomatis dimasukkan ke dalam karantina sementara (misal 15 menit). Di awal middleware, IP karantina langsung ditolak dengan HTTP 429 tanpa pemrosesan lanjutan.
### Alternatives Considered
- Memblokir permanen di tabel database SQL.
### Why Rejected
Tabel SQL lambat untuk pengecekan cepat tiap request. Cache TTL otomatis membersihkan jail setelah cooling-off period selesai tanpa intervensi manual.

---

## ADR-008: Multi-Vector Threat Scoring Correlation

### Status: Accepted
### Context
Serangan terkoordinasi biasanya menggabungkan reconnaissance, rotasi proxy, dan brute force dengan volume rendah agar tidak memicu threshold rule tunggal.
### Decision
Membangun `ThreatScoringEngine` yang mengagregasi skor risiko dari berbagai vektor serangan per IP/entitas dalam sliding window (misal 15 menit). Begitu skor akumulatif mencapai threshold (100), alert `compound_threat` tingkat critical diterbitkan.

---

## ADR-009: Background Queued Alert Delivery

### Status: Accepted
### Context
Panggilan HTTP sinkron ke Telegram Bot API, Discord Webhook, atau SIEM eksternal dapat menambah latency 100ms - 500ms pada response time pengguna.
### Decision
Menyediakan opsi `alerts.queue.enabled` menggunakan Laravel Queue Job (`DispatchAlertChannelJob`). Jika aktif, pengiriman notifikasi eksternal dilempar ke background worker tanpa membebani response HTTP request pengguna.
