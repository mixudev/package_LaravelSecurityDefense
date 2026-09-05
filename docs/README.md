# Dokumentasi Laravel Security Defense

Dokumentasi lengkap untuk integrasi, konfigurasi, operasional, dan arsitektur package `mixudev/security-defense`.

---

## Struktur Dokumentasi

### 1. Memulai (Getting Started)
- [Instalasi](./getting-started/installation.md) - Persyaratan sistem, instalasi via Composer, publish file config/migrasi, dan kredensial `.env`.
- [Quickstart](./getting-started/quickstart.md) - Panduan integrasi 5 menit (pendaftaran middleware WAF, listener telemetri auth, dan pengujian).
- [Referensi Konfigurasi](./getting-started/configuration.md) - Panduan lengkap setiap opsi pada `config/security-defense.php`.

### 2. Fitur Utama (Features)
- [Aturan Deteksi Ancaman](./features/detection-rules.md) - Penjelasan 11 aturan deteksi modular (Brute force, Stuffing, Spray, Injection, Travel, Recon, Scanner UA, Session Hijack, Velocity, Header Consistency).
- [Middleware WAF & Karantina IP](./features/waf-middleware.md) - Cara kerja `RequestThreatScanner`, mitigasi ReDoS, proteksi request flood, dan Fail2Ban auto-jailing.
- [Compound Threat Scoring](./features/threat-scoring.md) - Engine korelasi risiko multi-vektor dan eskalasi otomatis ke alert kritis.
- [Notifikasi Multi-Channel & Deduplikasi](./features/alert-channels.md) - Pengaturan channel Database, Telegram, Discord, Webhook (HMAC), Mail, serta deduplikasi alert.

### 3. Integrasi (Integrations)
- [Audit Perubahan Database & Deteksi Tamper](./integrations/data-audit.md) - Panduan penggunaan Trait `HasSecurityAudit`, masking kredensial, proteksi Mass Assignment, dan deteksi manipulasi parameter Burp Suite.
- [Session Intelligence & Pertahanan Klien](./integrations/session-intelligence.md) - Mitigasi pencurian cookie akibat malware infostealer (RedLine/Lumma), deteksi pembajakan sesi, dan post-auth scraping velocity.
- [CSP Armor & Data Hygiene](./integrations/csp-armor-and-pruning.md) - Proteksi Content Security Policy (CSP) transparan penangkal XSS dan pruning database skala jutaan user.
- [Ingesti Telemetri Autentikasi](./integrations/telemetry-ingestion.md) - Menghubungkan telemetri dari Laravel Breeze, Fortify, Sanctum, Passport, atau sistem kustom.
- [Bot Telegram Interaktif](./integrations/telegram-bot.md) - Setup Webhook produksi vs Polling lokal, menu kontrol panel, health check, dan remote pardon.
- [Integrasi Package mixudev/laravel-authentication](./integrations/laravel-auth-package.md) - Panduan subscriber event bridge dengan package autentikasi enterprise.

### 4. Operasional & Pemeliharaan (Operations)
- [Dashboard SIEM](./operations/dashboard.md) - Cara membuka dan mengamankan web dashboard pemantauan keamanan lokal, metrik, dan toggle tema.
- [Hardening Produksi](./operations/hardening.md) - Rekomendasi setup Redis, durabilitas karantina database, fast-path scanning, dan parameter self-defense.
- [Pengujian & Diagnostik](./operations/testing-and-diagnostics.md) - Menjalankan suite PHPUnit dan testing konektivitas channel via Artisan CLI.
- [Troubleshooting & FAQ](./operations/troubleshooting.md) - Solusi masalah umum (HTTP 403, tema Tailwind, antrean notifikasi, bypass karantina).

### 5. Arsitektur & Spesifikasi
- [Arsitektur & Prinsip Desain](./architecture/overview.md) - Pemisahan tanggung jawab (Auth vs Defense), alur pipeline data, dan privasi data.
- [Living Docs Internal Tim](./ai/README.md) - Catatan ADR (Architecture Decision Records), rincian implementasi class, dan changelog internal.
