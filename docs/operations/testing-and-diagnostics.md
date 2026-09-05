# Pengujian & Diagnostik

Panduan mengeksekusi test suite otomatis dan memeriksa konektivitas channel.

---

## 1. Menjalankan Test Suite Otomatis

Jalankan test suite menggunakan Composer dari direktori package:

```bash
composer test
```

Atau eksekusi langsung binary PHPUnit:

```bash
vendor/bin/phpunit
```

Cakupan pengujian mencakup:
- 8 Unit test aturan deteksi ancaman (Brute force, stuffing, spray, injection, travel, recon, UA anomaly).
- Uji batas Anti-ReDoS string length dan batasan rekursi array.
- Uji alur karantina IP (jail, pardon, whitelist, persistensi DB).
- Uji deduplikasi fingerprint dan rate limiter disk database.
- Pengujian saluran notifikasi Telegram, Discord, Webhook, dan Mail.
- Pengujian WAF middleware (pemblokiran SQLi, XSS, fast-path empty GET, HTTP 429 flood protection).
- Pengujian hak akses dashboard SIEM dan rendering data.

---

## 2. Diagnostik Saluran Notifikasi via Artisan CLI

Uji konektivitas dan keabsahan token/webhook channel tanpa perlu menunggu serangan nyata:

```bash
# Uji seluruh saluran sekaligus
php artisan security:test-webhook --all

# Uji saluran tertentu saja
php artisan security:test-webhook telegram
php artisan security:test-webhook discord
php artisan security:test-webhook webhook
php artisan security:test-webhook mail
```

Contoh keluaran tabel diagnostik:

```text
+----------+---------+-------------+----------+---------+----------------------+
| Channel  | Enabled | Configured  | Delivery | Latency | Diagnostic Message   |
+----------+---------+-------------+----------+---------+----------------------+
| DATABASE | YES     | YES         | SUCCESS  | -       | DB alert created     |
| TELEGRAM | YES     | YES         | SUCCESS  | 320 ms  | Message sent         |
| DISCORD  | YES     | YES         | SUCCESS  | 210 ms  | Embed sent           |
| WEBHOOK  | NO      | NO          | SKIPPED  | -       | Channel disabled     |
| MAIL     | YES     | YES         | SUCCESS  | 450 ms  | Mail queued/sent     |
+----------+---------+-------------+----------+---------+----------------------+
```

Kode keluar (*exit code*) adalah `0` jika berhasil dan `1` jika terjadi error, sangat cocok dipakai pada CI/CD pipeline pipeline health-check.

---

## 3. Diagnostik via Web Dashboard

Buka dashboard web (`/security-defense`), lalu klik tombol **Test Probe** pada masing-masing kartu channel di panel *Channels Hub*.
Endpoint uji coba ini dilindungi oleh token CSRF dan rate limit 10 request per menit per IP.
