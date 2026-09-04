# 02 — Integrasi (Cara Panggil Package)

Dokumen ini menjelaskan berbagai cara mengaktifkan dan memanggil
`mixudev/security-defense` dari aplikasi Laravel Anda.

---

## 1. Aktifkan WAF Middleware (Preventive Scanning + Quarantine)

Middleware `RequestThreatScanner` memindai setiap request masuk untuk melawan
SQLi, XSS, Path Traversal, OS Command Injection, bot/scanner, dan menerapkan
blokade IP quarantine (Fail2Ban defense).

### Laravel 11, 12, 13 (`bootstrap/app.php`)

```php
use Mixudev\SecurityDefense\Middleware\RequestThreatScanner;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        api: __DIR__.'/../routes/api.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware) {
        $middleware->append(RequestThreatScanner::class); // global, semua request
    })
    ->create();
```

### Laravel 10 (`app/Http/Kernel.php`)

```php
protected $middleware = [
    // ...
    \Mixudev\SecurityDefense\Middleware\RequestThreatScanner::class,
];
```

### Custom grup / hanya rute tertentu (opsional)

```php
use Mixudev\SecurityDefense\Middleware\RequestThreatScanner;

Route::middleware([RequestThreatScanner::class])->group(function () {
    // rute yang ingin dilindungi
});
```

---

## 2. Kirim Telemetry Auth (Deteksi Threat)

Package memonitor pola serangan dari data yang Anda kirim. Cara paling umum:
dengarkan event auth Laravel dan teruskan ke facade `SecurityDefense::record()`.

Di `AppServiceProvider::boot()` (atau `EventServiceProvider`):

```php
namespace App\Providers;

use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Lockout;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;
use Mixudev\SecurityDefense\Support\Facades\SecurityDefense;

class AppServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        // 1. Gagal login -> deteksi brute force / credential stuffing
        Event::listen(Failed::class, function (Failed $event) {
            SecurityDefense::record([
                'ip' => request()->ip(),
                'identifier' => $event->credentials['email'] ?? $event->credentials['username'] ?? 'unknown',
                'eventType' => 'LoginFailed',
                'userAgent' => request()->userAgent(),
                'metadata' => ['user_id' => $event->user?->id],
            ]);
        });

        // 2. Login sukses -> deteksi impossible travel
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

        // 3. Akun terkunci
        Event::listen(Lockout::class, function (Lockout $event) {
            SecurityDefense::record([
                'ip' => request()->ip(),
                'identifier' => (string) ($event->request->input('email') ?: 'unknown'),
                'eventType' => 'AccountLocked',
                'userAgent' => request()->userAgent(),
            ]);
        });
    }
}
```

Struktur payload `record()`:

| Field | Tipe | Wajib | Deskripsi |
|-------|------|-------|-----------|
| `ip` | string | wajib | Alamat IP pelaku |
| `identifier` | string | wajib | Identitas target (email/username/user id) |
| `eventType` | string | wajib | Nama event (`LoginFailed`, `LoginSucceeded`, dll) |
| `userAgent` | string | opsional | User-Agent request |
| `metadata` | array | opsional | Data tambahan (SANITIZED otomatis, password/token di-redact) |

> **Privasi:** Semua nilai sensitif (`password`, `token`, `cookie`, `secret`,
> header `authorization`) otomatis di-redact menjadi `[REDACTED]` oleh
> `Recursive Sanitizer Engine` sebelum disimpan / dikirim — tidak akan bocor.

---

## 3. Cara Panggil via Facade (Programatik)

Facade `SecurityDefense` menyediakan akses ke seluruh modul:

```php
use Mixudev\SecurityDefense\Support\Facades\SecurityDefense;
```

### 3a. Merekam event kustom (di luar auth default)

```php
SecurityDefense::record([
    'ip' => request()->ip(),
    'identifier' => 'order-12345',
    'eventType' => 'OrderFraudAttempt',
    'userAgent' => request()->userAgent(),
    'metadata' => ['coupon' => 'DISCOUNT99'],
]);
```

### 3b. Manajemen IP Quarantine

```php
// Cek apakah IP ter-quarantine
$isJailed = SecurityDefense::quarantine()->isQuarantined('198.51.100.22');

// Quarantine manual (1 jam = 3600 detik)
SecurityDefense::quarantine()->jail('198.51.100.22', 3600, 'Manual security block by admin');

// Lepas quarantine
SecurityDefense::quarantine()->pardon('198.51.100.22');

// Ambil detail quarantine
$details = SecurityDefense::quarantine()->getDetails('198.51.100.22');
// ['ip' => '...', 'jailed_at' => 1710000000, 'expires_at' => 1710003600, 'reason' => '...']
```

### 3c. Threat Scoring (inspeksi / reset skor risiko)

```php
// Skor risiko terakumulasi sebuah entitas (IP)
$score = SecurityDefense::scoring()->getScore(request()->ip());

// Reset skor (mis. setelah user lolos MFA / disetujui admin)
SecurityDefense::scoring()->resetScore(request()->ip());
```

### 3d. Resolusi Alert

```php
use Mixudev\SecurityDefense\Models\SecurityAlert;
use Mixudev\SecurityDefense\Support\Facades\SecurityDefense;

// Ambil alert baru severity critical
$alerts = SecurityAlert::new()->severity('critical')->get();

// Resolve alert
SecurityDefense::resolveAlert($alerts->first());
```

---

## 4. Dengarkan Domain Events

Aplikasi host bisa bereaksi terhadap event lifecycle package:

```php
use Mixudev\SecurityDefense\Events\ThreatDetected;
use Mixudev\SecurityDefense\Events\SecurityAlertCreated;
use Mixudev\SecurityDefense\Events\SecurityAlertResolved;
use Illuminate\Support\Facades\Event;

// Threat terdeteksi oleh detection engine
Event::listen(ThreatDetected::class, function (ThreatDetected $event) {
    // $event->threat      (SecurityThreat DTO)
    // $event->originEvent (SecurityEvent DTO)
});

// Alert baru dibuat & didispatch
Event::listen(SecurityAlertCreated::class, function (SecurityAlertCreated $event) {
    // $event->alert  (SecurityAlert Eloquent Model)
    // $event->threat (SecurityThreat DTO)
});

// Alert di-resolve
Event::listen(SecurityAlertResolved::class, function (SecurityAlertResolved $event) {
    // $event->alert
});
```

---

## 5. Contoh pakai Bersama Auth Sistem Populer

Package tidak terikat ke sistem auth manapun. Berikut mapping event umum:

| Sistem Auth | Event yang didengarkan |
|-------------|------------------------|
| Laravel Breeze / Fortify | `Illuminate\Auth\Events\Failed`, `Login`, `Lockout` |
| Laravel Jetstream | Sama seperti di atas |
| Sanctum (API token) | `Failed` (login), atau manual `record()` di login controller |
| Passport / OAuth | Manual `record()` di endpoint token |
| Custom JWT | Manual `record()` setelah validasi kredensial |

> **Prinsip:** `Authentication adalah gatekeeper; Security Defense adalah kamera
> keamanan & perisai proaktif.` Package TIDAK menggantikan user management,
> hashing password, session, atau captcha.

Lanjut ke [03-alert-channels.md](./03-alert-channels.md).
