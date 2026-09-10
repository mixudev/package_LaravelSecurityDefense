# Laravel Security Defense (`mixudev/security-defense`)

[![Versi Terbaru di Packagist](https://img.shields.io/packagist/v/mixudev/security-defense.svg?style=flat-square)](https://packagist.org/packages/mixudev/security-defense)
[![Release GitHub](https://img.shields.io/github/v/tag/mixudev/package_LaravelSecurityDefense?label=release&style=flat-square)](https://github.com/mixudev/package_LaravelSecurityDefense/releases)
[![Versi PHP](https://img.shields.io/badge/PHP-%5E8.2-blue.svg?style=flat-square)]()
[![Kompatibilitas Laravel](https://img.shields.io/badge/Laravel-10%20%7C%2011%20%7C%2012%20%7C%2013-red.svg?style=flat-square)]()
[![Lisensi: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](https://opensource.org/licenses/MIT)
[![Tests](https://img.shields.io/badge/tests-361%20%7C%201078%20assertions-brightgreen.svg?style=flat-square)]()

**`mixudev/security-defense`** adalah package pertahanan keamanan tingkat enterprise untuk aplikasi Laravel. Bertindak sebagai **"kamera pengawas, perisai proaktif, dan integritas data"** yang mendeteksi ancaman secara real-time, mengorelasikan pola serangan multi-vektor, mengisolasi penyerang (Fail2Ban IP Quarantine), memantau mutasi data & mendeteksi manipulasi parameter Burp Suite, melindungi sesi terautentikasi dari pencurian cookie malware, serta mengirimkan alert ter-deduplikasi ke berbagai saluran.

---

## Ringkasan Teknologi & Sistem

- **Decoupled Architecture**: Tidak menggantikan auth (user, session, hashing, atau token). Package murni mengonsumsi telemetri keamanan dari aplikasi.
- **11 Aturan Deteksi Modular**: Brute Force, Credential Stuffing, Distributed Spray, Rate Limit Bypass, Payload Injection (SQLi, XSS, command injection, traversal, SSRF/XXE, dan lainnya), Impossible Travel, Path Reconnaissance, User-Agent Anomaly, Session Fingerprint, Behavioral Velocity, dan HTTP Header Consistency.
- **Database Change Monitoring & Burp Tamper Detection**: Melacak mutasi database (`created`, `updated`, `deleted`), old vs new values, URL, method, actor, snapshot payload, dan mendeteksi injeksi parameter sensitif / mass assignment via Burp Suite dengan garansi *zero-leakage redaction* (password disamarkan).
- **Session Intelligence Layer**: Mendeteksi pencurian session cookie oleh malware di device korban (*infostealer*) serta scraping cepat pada akun yang sudah login.
- **Multi-Tab Security Dashboard**: Navigasi lengkap untuk Threat Telemetry SIEM, Database Mutations, dan Session Intelligence.
- **Compound Threat Scoring**: Menghitung akumulasi risiko antar jenis serangan pada entitas yang sama sepanjang waktu dan otomatis mengelevasi status ke ancaman kritis jika melampaui ambang batas.
- **Karantina IP Fail2Ban**: Memutus koneksi IP penyerang secara instan di awal middleware dengan HTTP 429, menghemat CPU hingga 99% saat diserang.
- **Fast-Path & Self-Defense Bounded**: Request GET/HEAD bersih tanpa body/query melewati scan regex secara instan. Dilengkapi proteksi Anti-ReDoS, batas memori rekursi, dan pembatas penulisan database.
- **Notifikasi Multi-Channel**: Database, Telegram, Discord, Webhook (tanda tangan HMAC-SHA256), dan Email native Laravel dengan dukungan antrean asinkron (queue).
- **Interactive Telegram Bot**: Kontrol panel interaktif via bot Telegram untuk health check, review insiden, dan unban IP.
- **Epistemic Security (opt-in)**: Pipeline berbasis evidence dengan confidence, risk, threat graph, policy, feedback, cache memory, provider AI advisory, dan response adapter default-off.

---

## Persyaratan Sistem

- PHP `^8.2`
- Laravel `10.x`, `11.x`, `12.x`, atau `13.x`
- Dependensi Composer runtime: PHP `^8.2`, `illuminate/support`, `illuminate/database`, `illuminate/cache`, `illuminate/http`, dan `illuminate/events` versi `^10.0|^11.0|^12.0|^13.0`
- Redis atau Memcached sangat disarankan untuk produksi; package tetap dapat memakai cache store aplikasi lain

---

## Panduan Instalasi & Aktivasi Singkat

### 1. Instalasi via Composer

```bash
composer require mixudev/security-defense
```

### 2. Publish Konfigurasi & Migrasi

```bash
php artisan vendor:publish --provider="Mixudev\SecurityDefense\Providers\SecurityDefenseServiceProvider"
php artisan migrate
```

### 3. Aktifkan WAF Middleware

Daftarkan middleware `RequestThreatScanner` agar seluruh request masuk dipindai dan dilindungi dari IP karantina:

#### Laravel 11, 12, 13 (`bootstrap/app.php`):
```php
use Mixudev\SecurityDefense\Middleware\RequestThreatScanner;

return Application::configure(basePath: dirname(__DIR__))
    ->withMiddleware(function (Middleware $middleware) {
        $middleware->append(RequestThreatScanner::class);
    })
    ->create();
```

#### Laravel 10 (`app/Http/Kernel.php`):
```php
protected $middleware = [
    // ...
    \Mixudev\SecurityDefense\Middleware\RequestThreatScanner::class,
];
```

### Setup dashboard satu perintah

```bash
php artisan security-defense:install --with-opaque-path
```

Command idempotent ini menjaga config custom, membuat `SECURITY_DEFENSE_DASHBOARD_PATH` secara aman jika belum ada, menyimpan secret hanya di `.env`, menjalankan migrasi, dan rebuild route cache. Token tidak pernah dicetak. Lihat [panduan instalasi](./docs/getting-started/installation.md) untuk semua opsi command dan [threat model](./docs/operations/security-threat-model.md) untuk rotasi secret.

### 4. Hubungkan Telemetri Autentikasi

Teruskan event autentikasi aplikasi ke `SecurityDefense::record()` pada `AppServiceProvider::boot()`:

```php
namespace App\Providers;

use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;
use Mixudev\SecurityDefense\Support\Facades\SecurityDefense;

class AppServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        // 1. Catat kegagalan login (Brute Force, Credential Stuffing)
        Event::listen(Failed::class, function (Failed $event) {
            SecurityDefense::record([
                'ip' => request()->ip(),
                'identifier' => $event->credentials['email'] ?? $event->credentials['username'] ?? 'unknown',
                'eventType' => 'LoginFailed',
                'userAgent' => request()->userAgent(),
                'metadata' => ['user_id' => $event->user?->id],
            ]);
        });

        // 2. Catat login sukses (Impossible Travel)
        Event::listen(Login::class, function (Login $event) {
            SecurityDefense::record([
                'ip' => request()->ip(),
                'identifier' => (string) $event->user->getAuthIdentifier(),
                'eventType' => 'LoginSucceeded',
                'userAgent' => request()->userAgent(),
                'metadata' => [
                    'latitude' => request()->header('CF-IPLatitude'),
                    'longitude' => request()->header('CF-IPLongitude'),
                    'country' => request()->header('CF-IPCountry'),
                ],
            ]);
        });
    }
}
```

### 5. Masukkan Kredensial Channel di `.env` (Opsional)

Aktivasi channel dilakukan di `config/security-defense.php`. File `.env` hanya digunakan untuk menyimpan kredensial:

```env
# Telegram Alerting
SECURITY_TELEGRAM_BOT_TOKEN=[REDACTED]
SECURITY_TELEGRAM_CHAT_ID=[REDACTED]

# Discord Webhook
SECURITY_DISCORD_WEBHOOK=[REDACTED]

# SIEM Webhook
SECURITY_WEBHOOK_URL=[REDACTED]
SECURITY_WEBHOOK_SECRET=[REDACTED]

# Email Alert
SECURITY_ALERT_EMAIL=[REDACTED]
```

Uji konektivitas channel melalui terminal:
```bash
php artisan security:test-webhook --all
```

---

## Manajemen Programatik Singkat

```php
use Mixudev\SecurityDefense\Support\Facades\SecurityDefense;

// Cek apakah IP sedang diblokir
$isBlocked = SecurityDefense::quarantine()->isQuarantined('198.51.100.22');

// Blokir IP manual (IP, durasi detik, alasan)
SecurityDefense::quarantine()->jail('198.51.100.22', 3600, 'Blokir manual admin');

// Bebaskan IP dari blokir
SecurityDefense::quarantine()->pardon('198.51.100.22');

// Dapatkan akumulasi skor risiko IP
$score = SecurityDefense::scoring()->getScore(request()->ip());
```

---

## Daftar Isi Dokumentasi Lengkap

Untuk panduan konfigurasi mendalam, detail arsitektur, dan operasional tingkat lanjut, silakan baca dokumentasi di folder [`docs/`](./docs/README.md):

### 1. Memulai (Getting Started)
- [docs/getting-started/installation.md](./docs/getting-started/installation.md) — Panduan instalasi langkah demi langkah, rincian migrasi database, dan penjelasan perlakuan konfigurasi vs kredensial `.env`.
- [docs/getting-started/quickstart.md](./docs/getting-started/quickstart.md) — Panduan integrasi kilat 5 menit untuk menyambungkan WAF middleware, listener telemetri auth, dan pengujian saluran.
- [docs/getting-started/configuration.md](./docs/getting-started/configuration.md) — Referensi lengkap setiap kunci konfigurasi pada file `config/security-defense.php` beserta nilai default-nya.

### 2. Fitur Keamanan (Features)
- [docs/features/detection-rules.md](./docs/features/detection-rules.md) — Penjelasan 11 aturan deteksi modular (Brute force, Stuffing, Spray, Bypass, Injection, Travel, Recon, Scanner UA, Session Fingerprint, Behavioral Velocity, Header Consistency).
- [docs/features/dashboard.md](./docs/features/dashboard.md) — Fitur dashboard monitoring: KPI, quick-action toggle, IP quarantine management, live WAF events, date range filter.
- [docs/features/waf-middleware.md](./docs/features/waf-middleware.md) — Penjelasan pipeline inspeksi middleware `RequestThreatScanner`, proteksi request flood, dan Fail2Ban auto-jailing.
- [docs/features/threat-scoring.md](./docs/features/threat-scoring.md) — Mekanisme kalkulasi skor risiko kumulatif multi-vektor dan eskalasi otomatis ke status compound threat.
- [docs/features/alert-channels.md](./docs/features/alert-channels.md) — Konfigurasi 5 saluran alert (Database, Telegram, Discord, Webhook HMAC, Email), deduplikasi fingerprint, dan antrean asinkron (queue).
- [docs/features/epistemic-security.md](./docs/features/epistemic-security.md) — Analisis threat berbasis evidence, confidence, risk, policy, graph, memory, feedback, dan provider AI advisory.

### 3. Integrasi Sistem (Integrations)
- [docs/integrations/data-audit.md](./docs/integrations/data-audit.md) — Panduan audit mutasi database, masking kredensial, dan deteksi manipulasi parameter Burp Suite.
- [docs/integrations/session-intelligence.md](./docs/integrations/session-intelligence.md) — Perlindungan session cookie dari infostealer malware, deteksi pembajakan sesi, dan scraping velocity.
- [docs/integrations/csp-armor-and-pruning.md](./docs/integrations/csp-armor-and-pruning.md) — Proteksi Content Security Policy (CSP) transparan penangkal XSS dan pruning log database untuk skala jutaan pengguna.
- [docs/integrations/telemetry-ingestion.md](./docs/integrations/telemetry-ingestion.md) — Cara menghubungkan event login dari Breeze, Fortify, Sanctum, Jetstream, atau custom JWT ke method `record()`.
- [docs/integrations/telegram-bot.md](./docs/integrations/telegram-bot.md) — Panduan lengkap kontrol panel bot Telegram: setup Webhook (server/cPanel tanpa daemon) vs Polling (localhost), menu health check, dan remote pardon.
- [docs/integrations/laravel-auth-package.md](./docs/integrations/laravel-auth-package.md) — Panduan integrasi khusus via Event Subscriber dengan package `mixudev/laravel-authentication`.
- [docs/integrations/auth-sync-command.md](./docs/integrations/auth-sync-command.md) — Command `auth:sync`: generate bridge subscriber agar defense mendengarkan semua event package `mixudev/laravel-authentication`, plus inject middleware WAF bila belum terdaftar.

### 4. Operasional & Pemeliharaan (Operations)
- [docs/operations/dashboard.md](./docs/operations/dashboard.md) — Cara mengakses web dashboard SIEM bawaan, pengamanan rute produksi via Laravel Gate, metrik, dan toggle tema.
- [docs/operations/security-threat-model.md](./docs/operations/security-threat-model.md) — Threat model & perimeter: trust boundaries, prosedur rotasi secret opaque path, dan skenario serangan lintas-batas (session theft, manipulasi jaringan, brute-force URL).
- [docs/operations/hardening.md](./docs/operations/hardening.md) — Panduan pengerasan produksi: konfigurasi Redis cache, persistensi karantina database, fast-path scanning, dan parameter self-defense.
- [docs/operations/testing-and-diagnostics.md](./docs/operations/testing-and-diagnostics.md) — Panduan eksekusi pengujian otomatis PHPUnit dan diagnostic probe saluran alert melalui Artisan CLI.
- [docs/operations/troubleshooting.md](./docs/operations/troubleshooting.md) — Solusi mengatasi kendala umum seperti error 403 dashboard, pesan alert tidak terkirim, dan penanganan cache flush.

### 5. Arsitektur & Prinsip Desain
- [docs/architecture/overview.md](./docs/architecture/overview.md) — Filosofi pemisahan tugas (Auth vs Defense), diagram pipeline keamanan, dan kebijakan privasi Zero-Leakage Sanitizer.
- [docs/ai/README.md](./docs/ai/README.md) — Dokumentasi living internal engineering (Architecture Decision Records, detail class implementasi, dan catatan perubahan versi).

---

## Pengujian

Jalankan test suite menggunakan PHPUnit:

```bash
composer test
```

---

## Lisensi

Didistribusikan di bawah lisensi MIT. Lihat file [LICENSE](LICENSE) untuk informasi lebih lanjut.
