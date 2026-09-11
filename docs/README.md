# Dokumentasi Laravel Security Defense

Selamat datang di dokumentasi resmi **mixudev/security-defense**. Package ini menyediakan sistem pertahanan keamanan aplikasi lapis ganda (defense-in-depth) untuk ekosistem Laravel: WAF adaptif, deteksi anomali perilaku (brute force, credential stuffing, impossible travel, distributed spray), analisis epistemik SIEM, karantina IP otomatis, channel alert real-time (Telegram, Webhook, Log), serta portal dashboard bertopeng dengan URL capability sekali pakai.

---

## Daftar Isi Dokumentasi

1. **[01. Panduan Instalasi](./01-instalasi.md)**
   - Persyaratan sistem & dependensi
   - Instalasi satu perintah via `php artisan security-defense:install`
   - Opsi instalasi (`--with-opaque-path`, `--force`, `--dry-run`)
   - Penerbitan views opsional

2. **[02. Panduan Konfigurasi](./02-konfigurasi.md)**
   - Struktur konfigurasi utama `config/security-defense.php`
   - Mekanisme runtime override `config/security-defense-overrides.php`
   - Tabel referensi switch fitur penting

3. **[03. Portal & Dashboard Opaque](./03-dashboard.md)**
   - Konsep keamanan gate `/security-defense`
   - One-time capability token terenkripsi AES-256-CBC + HMAC
   - Isolasi kunci via HKDF dari `APP_KEY` dan opsi `SECURITY_DEFENSE_KEY` (aman untuk DB klien)
   - Alias rute acak & proteksi local vs production

4. **[04. Integrasi Laravel Authentication](./04-integrasi-auth.md)**
   - Jembatan event otomatis via `php artisan auth:sync`
   - 12 domain event yang dipantau (Login, Lockout, OTP, Device, Password, Session)
   - Auto-injeksi WAF middleware ke pipeline HTTP

5. **[05. Fitur Keamanan & Mesin Deteksi](./05-fitur-keamanan.md)**
   - Preventive WAF (SQLi, XSS, Path Traversal, Command Injection, User-Agent Scanner Anomaly)
   - Behavioral Velocity & Brute Force Engine
   - Epistemic SIEM Analyzer (Bayesian correlation)
   - Sistem Karantina IP Otomatis & Saluran Alert (Telegram bot dua arah, Webhook)

6. **[06. Operasi, Hardening, dan Pemecahan Masalah](./06-operasi-dan-troubleshooting.md)**
   - Checklist hardening sebelum rilis production
   - Pemecahan masalah umum (403 Forbidden di local/production, route cache)
   - Perintah diagnosa dan pembersihan data berkala
