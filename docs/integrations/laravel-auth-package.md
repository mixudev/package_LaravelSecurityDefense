# Integrasi dengan `mixudev/laravel-authentication`

Panduan menghubungkan sistem deteksi `mixudev/security-defense` dengan package autentikasi enterprise `mixudev/laravel-authentication`.

---

## 1. Arsitektur Komunikasi

Kedua package sengaja dipisahkan secara modular tanpa dependensi langsung (*decoupled*). Komunikasi dilakukan via pola **Event Subscriber** di aplikasi host Laravel Anda.

```text
mixudev/laravel-authentication (Auth & Session Engine)
                     │
                     ▼ Domain Events
[Event Subscriber Aplikasi Host]
                     │
                     ▼ SecurityDefense::record()
mixudev/security-defense (WAF, SIEM, Scoring, & Karantina IP)
```

---

## 2. Pemetaan Event ke Telemetri

| Event `mixudev/laravel-authentication` | Telemetri `eventType` | Rule Deteksi Terkait |
|---|---|---|
| `Vendor\LaravelAuthentication\Events\LoginFailed` | `LoginFailed` | Brute Force, Credential Stuffing, Distributed Spray, Compound Scoring |
| `Vendor\LaravelAuthentication\Events\LoginSucceeded` | `LoginSucceeded` | Impossible Travel, Anomali User Agent |
| `Vendor\LaravelAuthentication\Events\AccountLocked` | `AccountLocked` | Telemetri Lockout & Forensik Audit |
| `Vendor\LaravelAuthentication\Events\NewDeviceLoginDetected` | `NewDeviceLoginDetected` | Impossible Travel, Anomali Sidik Jari Perangkat |
| `Vendor\LaravelAuthentication\Events\OtpVerified` | `OTP_VERIFIED` | Validasi Keberhasilan Multi-Factor (MFA) |

---

## 3. Implementasi Listener Subscriber

Buat file baru di `app/Listeners/AuthenticationSecuritySubscriber.php`:

```php
<?php

declare(strict_types=1);

namespace App\Listeners;

use Illuminate\Events\Dispatcher;
use Mixudev\SecurityDefense\Support\Facades\SecurityDefense;
use Vendor\LaravelAuthentication\Events\AccountLocked;
use Vendor\LaravelAuthentication\Events\LoginFailed;
use Vendor\LaravelAuthentication\Events\LoginSucceeded;

class AuthenticationSecuritySubscriber
{
    public function handleLoginFailed(LoginFailed $event): void
    {
        SecurityDefense::record([
            'ip' => $event->context->ipAddress,
            'identifier' => $event->identifier,
            'eventType' => 'LoginFailed',
            'timestamp' => now()->toIso8601String(),
            'userAgent' => $event->context->userAgent,
            'metadata' => array_filter([
                'reason' => $event->reason,
                'channel' => $event->context->channel->value,
                'user_id' => $event->user?->getAuthIdentifier(),
                'headers' => $event->context->headers,
            ]),
        ]);
    }

    public function handleLoginSucceeded(LoginSucceeded $event): void
    {
        $identifier = (string) ($event->user->email ?? $event->user->username ?? $event->user->getAuthIdentifier());

        SecurityDefense::record([
            'ip' => $event->context->ipAddress,
            'identifier' => $identifier,
            'eventType' => 'LoginSucceeded',
            'timestamp' => now()->toIso8601String(),
            'userAgent' => $event->context->userAgent,
            'metadata' => array_filter([
                'strategy' => $event->strategy,
                'channel' => $event->context->channel->value,
                'user_id' => $event->user->getAuthIdentifier(),
                'headers' => $event->context->headers,
            ]),
        ]);
    }

    public function handleAccountLocked(AccountLocked $event): void
    {
        $identifier = (string) ($event->user->email ?? $event->user->username ?? $event->user->getAuthIdentifier());

        SecurityDefense::record([
            'ip' => $event->context->ipAddress,
            'identifier' => $identifier,
            'eventType' => 'AccountLocked',
            'timestamp' => now()->toIso8601String(),
            'userAgent' => $event->context->userAgent,
            'metadata' => [
                'lockout_duration_minutes' => $event->lockoutDurationMinutes,
                'user_id' => $event->user->getAuthIdentifier(),
            ],
        ]);
    }

    public function subscribe(Dispatcher $events): array
    {
        return [
            LoginFailed::class => 'handleLoginFailed',
            LoginSucceeded::class => 'handleLoginSucceeded',
            AccountLocked::class => 'handleAccountLocked',
        ];
    }
}
```

Daftarkan subscriber di `AppServiceProvider::boot()`:

```php
Event::subscribe(\App\Listeners\AuthenticationSecuritySubscriber::class);
```
