# Ingesti Telemetri & Integrasi Autentikasi

`mixudev/security-defense` dirancang secara *decoupled*. Package ini tidak menggantikan fungsi autentikasi inti Laravel, melainkan bertindak sebagai pengonsumsi telemetri.

---

## 1. Kompatibilitas Sistem Autentikasi

Package dapat dihubungkan dengan berbagai sistem autentikasi Laravel:
- Laravel Breeze, Fortify, atau Jetstream
- Laravel Sanctum atau Passport (API Token)
- Implementasi custom JWT / OAuth
- Package autentikasi khusus (seperti `mixudev/laravel-authentication`)

---

## 2. Format Data Telemetri Masuk

Telemetri dikirim ke package menggunakan method `SecurityDefense::record()`:

```php
use Mixudev\SecurityDefense\Support\Facades\SecurityDefense;

SecurityDefense::record([
    'ip' => '203.0.113.195',
    'identifier' => 'admin@domain.com', // Email, username, atau ID pengguna
    'eventType' => 'LoginFailed',        // LoginFailed, LoginSucceeded, OTP_FAILED, dll
    'timestamp' => now()->toIso8601String(),
    'userAgent' => request()->userAgent(),
    'metadata' => [
        'reason' => 'invalid_password',
        'user_id' => 42,
    ],
]);
```

Semua data metadata yang dikirimkan diproses secara rekursif oleh engine `Sanitizer`. Field-field sensitif (`password`, `token`, `secret`, `authorization`, `cookie`) otomatis disensor menjadi `[REDACTED]`.

---

## 3. Integrasi via Event Autentikasi Bawaan Laravel

Tambahkan listener pada file `AppServiceProvider::boot()`:

```php
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Lockout;
use Illuminate\Support\Facades\Event;
use Mixudev\SecurityDefense\Support\Facades\SecurityDefense;

// 1. Kegagalan login -> Mendeteksi Brute Force & Password Spray
Event::listen(Failed::class, function (Failed $event) {
    SecurityDefense::record([
        'ip' => request()->ip(),
        'identifier' => $event->credentials['email'] ?? $event->credentials['username'] ?? 'unknown',
        'eventType' => 'LoginFailed',
        'userAgent' => request()->userAgent(),
        'metadata' => [
            'user_id' => $event->user?->getAuthIdentifier(),
        ],
    ]);
});

// 2. Login berhasil -> Mendeteksi Impossible Travel
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

// 3. Penguncian akun akibat rate-limiting
Event::listen(Lockout::class, function (Lockout $event) {
    SecurityDefense::record([
        'ip' => request()->ip(),
        'identifier' => (string) ($event->request->input('email') ?: 'unknown'),
        'eventType' => 'AccountLocked',
        'userAgent' => request()->userAgent(),
    ]);
});
```
