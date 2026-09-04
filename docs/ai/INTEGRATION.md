# Integration Guide — `mixudev/security-defense`

Dokumen ini menjelaskan cara mengintegrasikan `mixudev/security-defense` ke dalam aplikasi Laravel.

---

## 1. Instalasi

Tambahkan package via Composer:

```bash
composer require mixudev/security-defense
```

Publikasikan konfigurasi dan migrasi:

```bash
php artisan vendor:publish --provider="Mixudev\SecurityDefense\Providers\SecurityDefenseServiceProvider"
php artisan migrate
```

---

## 2. Integrasi Source Adapter

Package dapat menerima security data secara terprogram atau via event listener:

### A. Menggunakan Facade

```php
use Mixudev\SecurityDefense\Support\Facades\SecurityDefense;

SecurityDefense::record([
    'ip' => request()->ip(),
    'identifier' => $request->input('email'),
    'eventType' => 'LoginFailed',
    'timestamp' => now()->toIso8601String(),
    'userAgent' => request()->userAgent(),
    'metadata' => [
        'attempt_type' => 'password_auth',
    ],
]);
```

### B. Meneruskan Laravel Auth Events

Di `EventServiceProvider` host application:

```php
use Illuminate\Auth\Events\Failed;
use Mixudev\SecurityDefense\Support\Facades\SecurityDefense;

Event::listen(Failed::class, function (Failed $event) {
    SecurityDefense::record([
        'ip' => request()->ip(),
        'identifier' => $event->credentials['email'] ?? $event->credentials['username'] ?? 'unknown',
        'eventType' => 'LoginFailed',
        'timestamp' => now()->toIso8601String(),
        'userAgent' => request()->userAgent(),
        'metadata' => [
            'user_id' => $event->user?->id,
        ],
    ]);
});
```

---

## 3. Integrasi Middleware `RequestThreatScanner`

Tambahkan middleware ke grup `web` atau `api` di `bootstrap/app.php` (Laravel 11+) atau `app/Http/Kernel.php`:

```php
// bootstrap/app.php (Laravel 11+)
->withMiddleware(function (Middleware $middleware) {
    $middleware->append(\Mixudev\SecurityDefense\Middleware\RequestThreatScanner::class);
})
```

Middleware ini otomatis:
1. Menolak request dari IP yang sedang di-quarantine secara instan (HTTP 429).
2. Memeriksa scanner otomatis (`sqlmap`, `nikto`, `gobuster`).
3. Memeriksa probe ke file sensitif (`.env`, `.git`, `phpinfo`, dll).
4. Memindai payload SQLi, XSS, Path Traversal dengan batas anti-ReDoS.
5. Menjebloskan IP penyerang ke karantina secara otomatis jika serangan kritis terdeteksi.

---

## 4. Manajemen IP Quarantine Secara Terprogram

Host application dapat mengelola karantina IP langsung via Facade:

```php
use Mixudev\SecurityDefense\Support\Facades\SecurityDefense;

// Cek status karantina
$isJailed = SecurityDefense::quarantine()->isQuarantined('198.51.100.5');

// Masukkan IP ke karantina manual selama 30 menit (1800 detik)
SecurityDefense::quarantine()->jail('198.51.100.5', 1800, 'Manual admin block');

// Lepaskan IP dari karantina (pardon)
SecurityDefense::quarantine()->pardon('198.51.100.5');

// Ambil detail karantina
$details = SecurityDefense::quarantine()->getDetails('198.51.100.5');
```

---

## 5. Pemeriksaan Akumulasi Skor Risiko (Threat Scoring)

```php
use Mixudev\SecurityDefense\Support\Facades\SecurityDefense;

// Ambil akumulasi skor risiko IP penyerang
$currentScore = SecurityDefense::scoring()->getScore(request()->ip());

// Reset skor (misal setelah pengguna menyelesaikan verifikasi Captcha/MFA)
SecurityDefense::scoring()->resetScore(request()->ip());
```

---

## 6. Mengaktifkan Background Queue untuk Notifikasi

Untuk memastikan response time HTTP aplikasi tetap instan (< 20ms) tanpa terbebani I/O jaringan Telegram/Discord/SIEM, cukup ubah di file `.env`:

```env
SECURITY_DEFENSE_QUEUE_ENABLED=true
SECURITY_DEFENSE_QUEUE_CONNECTION=redis
SECURITY_DEFENSE_QUEUE_NAME=security-alerts
```

Dan jalankan queue worker standar Laravel:

```bash
php artisan queue:work --queue=security-alerts
```
