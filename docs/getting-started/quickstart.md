# Quickstart

Panduan integrasi ringkas untuk mengaktifkan proteksi dalam 5 menit.

---

## 1. Daftarkan Middleware WAF (`RequestThreatScanner`)

Middleware ini memindai request HTTP masuk terhadap injeksi SQL, XSS, Path Traversal, bot scanner, dan menegakkan blokir karantina IP Fail2Ban.

### Laravel 11, 12, 13 (`bootstrap/app.php`):

```php
use Mixudev\SecurityDefense\Middleware\RequestThreatScanner;

return Application::configure(basePath: dirname(__DIR__))
    ->withMiddleware(function (Middleware $middleware) {
        $middleware->append(RequestThreatScanner::class);
    })
    ->create();
```

### Laravel 10 (`app/Http/Kernel.php`):

```php
protected $middleware = [
    // ...
    \Mixudev\SecurityDefense\Middleware\RequestThreatScanner::class,
];
```

---

## 2. Hubungkan Telemetri Autentikasi

Kirim event autentikasi aplikasi Anda ke method `SecurityDefense::record()`. Tambahkan listener pada `AppServiceProvider::boot()`:

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
        // 1. Kegagalan login (Brute Force, Credential Stuffing, Distributed Spray)
        Event::listen(Failed::class, function (Failed $event) {
            SecurityDefense::record([
                'ip' => request()->ip(),
                'identifier' => $event->credentials['email'] ?? $event->credentials['username'] ?? 'unknown',
                'eventType' => 'LoginFailed',
                'userAgent' => request()->userAgent(),
                'metadata' => [
                    'user_id' => $event->user?->id,
                ],
            ]);
        });

        // 2. Login berhasil (Impossible Travel & Device Anomaly)
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

---

## 3. Masukkan Kredensial Notifikasi di `.env`

Isi kredensial bot Telegram atau Discord Webhook di `.env` aplikasi Anda:

```env
SECURITY_TELEGRAM_BOT_TOKEN=123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ
SECURITY_TELEGRAM_CHAT_ID=-1001234567890

SECURITY_DISCORD_WEBHOOK=https://discord.com/api/webhooks/123456789/token_here
```

Uji pengiriman notifikasi dengan command:

```bash
php artisan security:test-webhook --all
```
