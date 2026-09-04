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

### A. Menggunakan Facade / Injeksi Langsung

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

Tambahkan middleware ke grup `web` atau `api` di `app/Http/Kernel.php` atau `bootstrap/app.php` (Laravel 11+):

```php
// bootstrap/app.php (Laravel 11)
->withMiddleware(function (Middleware $middleware) {
    $middleware->append(\Mixudev\SecurityDefense\Middleware\RequestThreatScanner::class);
})
```

Middleware ini akan memeriksa query string, request body, dan header berbahaya (SQLi, XSS, Path Traversal) sebelum request diteruskan ke controller.

---

## 4. Mendengarkan Domain Events

Package memancarkan event berikut yang dapat di-listen oleh aplikasi host:

1. `Mixudev\SecurityDefense\Events\ThreatDetected`: Saat anomali terdeteksi oleh Detection Engine.
2. `Mixudev\SecurityDefense\Events\SecurityAlertCreated`: Saat alert baru berhasil disimpan dan didispatch.
3. `Mixudev\SecurityDefense\Events\SecurityAlertResolved`: Saat alert diselesaikan oleh admin.
