# Laravel Security Defense (`mixudev/security-defense`)

[![Versi Terbaru di Packagist](https://img.shields.io/packagist/v/mixudev/security-defense.svg?style=flat-square)](https://packagist.org/packages/mixudev/security-defense)
[![Release GitHub](https://img.shields.io/github/v/tag/mixudev/package_LaravelSecurityDefense?label=release&style=flat-square)](https://github.com/mixudev/package_LaravelSecurityDefense/releases)
[![Versi PHP](https://img.shields.io/badge/PHP-%5E8.2-blue.svg?style=flat-square)]()
[![Kompatibilitas Laravel](https://img.shields.io/badge/Laravel-10%20%7C%2011%20%7C%2012%20%7C%2013-red.svg?style=flat-square)]()
[![Lisensi: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](https://opensource.org/licenses/MIT)
|![Tests](https://img.shields.io/badge/tests-406%20%7C%201289%20assertions-brightgreen.svg?style=flat-square)()|

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

Command idempotent ini menjaga config custom, mengaktifkan flow opaque dashboard, menjalankan migrasi, dan me-rebuild route cache. URL dashboard diturunkan dari `APP_KEY` via HKDF (AES-256-CBC + HMAC-SHA256), sekali pakai (one-time nonce), dan terikat sesi — tanpa token manual di `.env`. Untuk isolasi total dari enkripsi database host, set `SECURITY_DEFENSE_KEY` (opsional): rotasi kunci dashboard lalu tidak menyentuh data terenkripsi / sesi klien. Lihat [panduan instalasi](./docs/01-instalasi.md) untuk detail dan [operasi & troubleshooting](./docs/06-operasi-dan-troubleshooting.md).

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

Dokumentasi lengkap telah diringkas secara modular menjadi 6 panduan utama berbahasa Indonesia pada folder [`docs/`](./docs/README.md):

1. **[01. Panduan Instalasi](./docs/01-instalasi.md)** — Instalasi satu perintah `php artisan security-defense:install --with-opaque-path`, migrasi, dan penerbitan view opsional.
2. **[02. Panduan Konfigurasi](./docs/02-konfigurasi.md)** — Tabel referensi lengkap konfigurasi `config/security-defense.php` dan sistem runtime override.
3. **[03. Portal & Dashboard Opaque](./docs/03-dashboard.md)** — Arsitektur gate verifikasi, rotasi path sesi non-deterministik, idle timeout, anti-replay, Trusted Proxies, dan log redaction.
4. **[04. Integrasi Laravel Authentication](./docs/04-integrasi-auth.md)** — Menghubungkan 12 domain event otentikasi via perintah `php artisan auth:sync` dan auto-injeksi middleware WAF.
5. **[05. Fitur Keamanan & Mesin Deteksi](./docs/05-fitur-keamanan.md)** — WAF preventif, kalkulasi risiko kumulatif, Epistemic SIEM Analyzer, sistem karantina IP, dan alert interaktif Telegram/Webhook.
6. **[06. Operasi, Hardening, dan Troubleshooting](./docs/06-operasi-dan-troubleshooting.md)** — Checklist pengerasan production, solusi kendala 403/404, dan panduan pemeliharaan rutin.

---

## Pengujian

Jalankan test suite menggunakan PHPUnit:

```bash
composer test
```

---

## Lisensi

Didistribusikan di bawah lisensi MIT. Lihat file [LICENSE](LICENSE) untuk informasi lebih lanjut.
