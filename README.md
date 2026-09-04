# Laravel Security Defense (`mixudev/security-defense`)

[![Latest Version on Packagist](https://img.shields.io/packagist/v/mixudev/security-defense.svg?style=flat-square)](https://packagist.org/packages/mixudev/security-defense)
[![GitHub Release](https://img.shields.io/github/v/tag/mixudev/package_LaravelSecurityDefense?label=release&style=flat-square)](https://github.com/mixudev/package_LaravelSecurityDefense/releases)
[![Tests Passing](https://img.shields.io/badge/tests-34%20passed-brightgreen.svg?style=flat-square)]()
[![PHP Version](https://img.shields.io/badge/PHP-%5E8.2-blue.svg?style=flat-square)]()
[![Laravel Compatibility](https://img.shields.io/badge/Laravel-10%20%7C%2011%20%7C%2012%20%7C%2013-red.svg?style=flat-square)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](https://opensource.org/licenses/MIT)

**`mixudev/security-defense`** is an enterprise-grade, modular, and configurable security defense package for Laravel applications. Designed as an intelligent **"security camera and proactive shield"** (telemetry correlation, multi-vector threat scoring, automated IP quarantine, deduplicated multi-channel alerting, and preventive WAF payload scanning) without duplicating or coupling to specific authentication systems.

---

## 🏛️ Core Principle

> **"Authentication is the gatekeeper. Security Defense is the security camera and proactive shield."**

`mixudev/security-defense` **does not duplicate authentication responsibilities**. It will never replace your user management, password hashing, session tokens, audit logs, captchas, or custom rate-limiters. Instead, it consumes security telemetry emitted by your application, correlates multi-request attack patterns, manages deduplicated alerts across multiple channels, and blocks dangerous payloads at the network boundary before reaching your controllers.

---

## 📐 Architecture Overview

```text
Incoming HTTP Request / Security Telemetry
                    │
                    ▼
┌─────────────────────────────────────────────────────────────┐
│ mixudev/security-defense Pipeline                           │
│                                                             │
│  [1. Active IP Quarantine Layer]                            │
│      └── Instantly rejects quarantined IPs (HTTP 429)       │
│          with ZERO CPU regex overhead during active DoS     │
│                                                             │
│  [2. Preventive WAF Middleware (RequestThreatScanner)]      │
│      ├── Anti-ReDoS Truncator (Safe string length limits)   │
│      ├── User-Agent Fingerprinter (sqlmap, nikto, bots)     │
│      ├── Path Reconnaissance Probe (.env, .git, dumps)      │
│      └── Payload Injection Inspector (SQLi, XSS, RCE)       │
│          └── Auto-jails attacker IP if critical threat      │
│                                                             │
│  [3. Normalized Telemetry Bridge (ThreatSource)]            │
│      ├── GenericArraySource & RequestThreatSource           │
│      └── Recursive Sanitizer Engine (Zero-Leakage Policy)   │
│                                                             │
│  [4. Stateless Detection Engine (8 Modular Rules)]          │
│      ├── BruteForceRule            (Single target overload) │
│      ├── CredentialStuffingRule    (1 IP -> many targets)   │
│      ├── DistributedSprayRule      (Many IPs -> 1 target)   │
│      ├── RateLimitBypassRule       (Proxy chain spoofing)   │
│      ├── PayloadInjectionRule      (SQLi, XSS, Traversal)   │
│      ├── ImpossibleTravelRule      (Haversine velocity check│
│      ├── PathReconnaissanceRule    (Sensitive file scans)   │
│      └── UserAgentAnomalyRule      (Automated attack tools) │
│                                                             │
│  [5. Compound Threat Scoring Engine]                        │
│      └── Multi-vector risk accumulation per IP/target       │
│          Triggers CRITICAL compound_threat when score >= 100│
│                                                             │
│  [6. Deduplication & Anti-Disk Flood Limiter]              │
│      ├── Alert Rate Limiter (Protects DB disk from storms)  │
│      └── AlertDeduplicator (Fingerprint SHA-256 + Window)   │
│                                                             │
│  [7. Multi-Channel Alert Dispatcher]                        │
│      ├── DatabaseChannel (Mandatory Model: SecurityAlert)   │
│      ├── TelegramChannel (Sync / Background Queue)          │
│      ├── DiscordChannel (Sync / Background Queue)           │
│      └── WebhookChannel (Sync / Background Queue via HMAC)  │
│                                                             │
│  [8. Domain Events]                                         │
│      ├── ThreatDetected                                     │
│      ├── SecurityAlertCreated                               │
│      └── SecurityAlertResolved                              │
└─────────────────────────────────────────────────────────────┘
```

---

## ⚡ Features & Capabilities

- **Universal ThreatSource Ingestion**: Ingest security events from any authentication system (Laravel Breeze, Fortify, Jetstream, Sanctum, Passport, custom JWT, API tokens) without hardcoded dependencies.
- **8 Stateless Detection Rules**:
  - `BruteForceRule`: Sliding-window detection of repeated failed attempts on a single account.
  - `CredentialStuffingRule`: Probing multiple distinct accounts from a single IP.
  - `DistributedSprayRule`: Probing a single account across multiple distinct IPs.
  - `RateLimitBypassRule`: Proxy chain manipulation (`X-Forwarded-For`) and rapid IP cycling.
  - `PayloadInjectionRule`: SQL Injection, XSS, Path Traversal, and OS Command Injection detection.
  - `ImpossibleTravelRule`: Physical velocity check (Haversine formula) between successive logins.
  - `PathReconnaissanceRule`: Reconnaissance scans targeting sensitive files (`.env`, `.git`, `wp-admin`, database dumps).
  - `UserAgentAnomalyRule`: Hostile automated scanner fingerprinting (`sqlmap`, `nikto`, `dirbuster`, `gobuster`, etc.).
- **Multi-Vector Compound Threat Scoring**: Automatically correlates different attacks from the same entity over time. An IP that fails logins (+35), cycles proxy headers (+20), and probes SQLi (+50) accumulates a risk score of 105, escalating immediately to a `CRITICAL` compound threat.
- **Active IP Quarantine (Fail2Ban-Style Defense)**: Automatically isolates malicious IPs in cache for a configurable duration (default 15 minutes). Subsequent requests from quarantined IPs are rejected at the entrance of middleware with **HTTP 429**, saving up to 99% of CPU resources during DDoS attacks.
- **Self-Defense Hardening (Zero Vulnerability Guarantees)**:
  - **Anti-ReDoS**: All inspected strings are bounded by `max_inspection_length` (default 4096 chars) before regex evaluation, preventing catastrophic backtracking.
  - **Anti-Memory Exhaustion**: Nested array inputs are limited by `max_traversal_depth` (default 5 levels).
  - **Anti-Disk Exhaustion**: Database alert rate limiter restricts write frequency (default 60 alerts/minute).
  - **Zero-Leakage Sanitizer**: Passwords, tokens, cookies, secrets, and authorization headers are recursively redacted to `[REDACTED]` before storage or dispatching.
- **Asynchronous Queued Alert Dispatching**: Offload external webhook and chat notifications to Laravel background queues (`ShouldQueue`) for **zero request latency overhead** (< 20ms).
- **Zero Database Collision**: Uses a dedicated, customizable table (`security_alerts`) with no hardcoded foreign keys to `users`.

---

## 📦 Installation

Install the package via Composer:

```bash
composer require mixudev/security-defense
```

Publish the configuration file and database migrations:

```bash
php artisan vendor:publish --provider="Mixudev\SecurityDefense\Providers\SecurityDefenseServiceProvider"
```

Run migrations:

```bash
php artisan migrate
```

---

## 🚀 Quick Setup Guide

### 1. Register Preventive WAF Middleware

To automatically protect all inbound requests against SQLi, XSS, Path Traversal, Bot scanners, and enforce IP quarantine:

#### Laravel 11, 12, 13 (`bootstrap/app.php`):
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

---

### 2. Connect Authentication Telemetry

Connect your authentication events to the defense engine. In your `AppServiceProvider` (or `EventServiceProvider`):

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
        // 1. Capture failed authentication attempts
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

        // 2. Capture successful logins (for Impossible Travel detection)
        Event::listen(Login::class, function (Login $event) {
            SecurityDefense::record([
                'ip' => request()->ip(),
                'identifier' => (string) $event->user->getAuthIdentifier(),
                'eventType' => 'LoginSucceeded',
                'userAgent' => request()->userAgent(),
                'metadata' => [
                    // Optional: include GeoIP coordinates if using Torann/GeoIP or Stevebauman/Location
                    'latitude' => request()->header('CF-IPLatitude'),
                    'longitude' => request()->header('CF-IPLongitude'),
                    'country' => request()->header('CF-IPCountry'),
                ],
            ]);
        });

        // 3. Capture account lockouts
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

### 3. Configure Alert Channels in `.env`

You can enable Telegram, Discord, Webhooks, and background queuing directly via environment variables:

```env
# Master Toggle
SECURITY_DEFENSE_ENABLED=true

# Background Queue (Zero Latency Overhead)
SECURITY_DEFENSE_QUEUE_ENABLED=true
SECURITY_DEFENSE_QUEUE_CONNECTION=redis
SECURITY_DEFENSE_QUEUE_NAME=security-alerts

# IP Quarantine (Fail2Ban)
SECURITY_QUARANTINE_ENABLED=true

# Telegram Alerts
SECURITY_TELEGRAM_ENABLED=true
SECURITY_TELEGRAM_BOT_TOKEN=123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ
SECURITY_TELEGRAM_CHAT_ID=-1001234567890

# Discord Alerts
SECURITY_DISCORD_ENABLED=true
SECURITY_DISCORD_WEBHOOK=https://discord.com/api/webhooks/123456789/token_here

# Webhook / SIEM Alerts
SECURITY_WEBHOOK_ENABLED=false
SECURITY_WEBHOOK_URL=https://siem.example.com/api/v1/alerts
SECURITY_WEBHOOK_SECRET=your-hmac-sha256-signing-secret
```

---

## 🛠️ Programmatic Management

### Managing IP Quarantine

```php
use Mixudev\SecurityDefense\Support\Facades\SecurityDefense;

// Check if an IP is currently quarantined
$isJailed = SecurityDefense::quarantine()->isQuarantined('198.51.100.22');

// Quarantine an IP for 1 hour (3600 seconds)
SecurityDefense::quarantine()->jail('198.51.100.22', 3600, 'Manual security block by admin');

// Release an IP from quarantine immediately
SecurityDefense::quarantine()->pardon('198.51.100.22');

// Retrieve quarantine metadata
$details = SecurityDefense::quarantine()->getDetails('198.51.100.22');
// Returns: ['ip' => '...', 'jailed_at' => 1710000000, 'expires_at' => 1710003600, 'reason' => '...']
```

### Inspecting Threat Scores

```php
use Mixudev\SecurityDefense\Support\Facades\SecurityDefense;

// Retrieve the current accumulated risk score of an entity
$score = SecurityDefense::scoring()->getScore(request()->ip());

// Reset the threat score (e.g., after user passes biometric/MFA challenge)
SecurityDefense::scoring()->resetScore(request()->ip());
```

### Resolving Security Alerts

```php
use Mixudev\SecurityDefense\Models\SecurityAlert;
use Mixudev\SecurityDefense\Support\Facades\SecurityDefense;

// Fetch new alerts
$alerts = SecurityAlert::new()->severity('critical')->get();

// Resolve an alert
SecurityDefense::resolveAlert($alerts->first());
```

### Listening to Domain Events

Host applications can listen to lifecycle events emitted by the package:

```php
use Mixudev\SecurityDefense\Events\ThreatDetected;
use Mixudev\SecurityDefense\Events\SecurityAlertCreated;
use Mixudev\SecurityDefense\Events\SecurityAlertResolved;

Event::listen(ThreatDetected::class, function (ThreatDetected $event) {
    // $event->threat (SecurityThreat DTO)
    // $event->originEvent (SecurityEvent DTO)
});

Event::listen(SecurityAlertCreated::class, function (SecurityAlertCreated $event) {
    // $event->alert (SecurityAlert Eloquent Model)
    // $event->threat (SecurityThreat DTO)
});
```

---

## ⚙️ Configuration Reference

| Option | Env Variable | Default | Description |
|---|---|---|---|
| `enabled` | `SECURITY_DEFENSE_ENABLED` | `true` | Master toggle for detection, alerting, and WAF middleware. |
| `cache_store` | `SECURITY_DEFENSE_CACHE_STORE` | `null` | Cache store used for sliding windows, scoring, and quarantine. |
| `hardening.max_inspection_length` | — | `4096` | Maximum string length scanned by regex (Anti-ReDoS). |
| `hardening.max_traversal_depth` | — | `5` | Maximum recursion depth for nested input arrays. |
| `hardening.alert_rate_limit.max_alerts_per_minute` | — | `60` | Maximum database alert writes per minute (Anti-Disk Flood). |
| `detection.scoring.enabled` | — | `true` | Enables compound multi-vector threat scoring. |
| `detection.scoring.threshold` | — | `100` | Cumulative score required to trigger a CRITICAL compound threat. |
| `detection.scoring.window` | — | `900` | Score accumulation sliding window (15 minutes). |
| `middleware.quarantine.enabled` | `SECURITY_QUARANTINE_ENABLED` | `true` | Enables active IP quarantine (Fail2Ban defense). |
| `middleware.quarantine.duration` | — | `900` | Default quarantine duration in seconds (15 minutes). |
| `middleware.quarantine.auto_jail_on_critical` | — | `true` | Automatically quarantine IPs that trigger critical payload injection. |
| `middleware.payload_scanner.action` | — | `'block'` | Action on threat: `'block'` (HTTP 403) or `'log_only'`. |
| `alerts.queue.enabled` | `SECURITY_DEFENSE_QUEUE_ENABLED` | `false` | Offloads Telegram/Discord/Webhook notifications to Laravel queue. |
| `alerts.database.table` | `SECURITY_DEFENSE_TABLE` | `'security_alerts'` | Custom name for the security alerts database table. |

---

## 📚 AI Living Documentation

In-depth architectural design decisions, threat modeling, and integration specifications are maintained in `docs/ai/`:

- [README.md](docs/ai/README.md) - Documentation Index
- [ARCHITECTURE.md](docs/ai/ARCHITECTURE.md) - Architectural model, data flow, and separation of concerns
- [DECISIONS.md](docs/ai/DECISIONS.md) - Architecture Decision Records (ADR-001 through ADR-009)
- [IMPLEMENTATION.md](docs/ai/IMPLEMENTATION.md) - Component and class-level implementation details
- [SECURITY.md](docs/ai/SECURITY.md) - Self-defense, DoS mitigations, and zero-leakage privacy guarantees
- [CONFIGURATION.md](docs/ai/CONFIGURATION.md) - Full configuration option reference
- [INTEGRATION.md](docs/ai/INTEGRATION.md) - Integration guides for auth systems, WAF, and queue workers
- [TESTING.md](docs/ai/TESTING.md) - Test strategy and verification results (34/34 passing)
- [CHANGELOG.md](docs/ai/CHANGELOG.md) - Semantic release version history
- [TODO.md](docs/ai/TODO.md) - Development roadmap status

---

## 🧪 Testing

The package includes a comprehensive test suite covering unit tests, detection rules, anti-ReDoS bounds, IP quarantine, and feature workflows.

Run tests via Composer:

```bash
composer test
```

Or directly via PHPUnit:

```bash
./vendor/bin/phpunit
```

Output:
```text
PHPUnit 11.5.56 by Sebastian Bergmann and contributors.
Runtime:       PHP 8.5.4
Configuration: phpunit.xml

..................................                                34 / 34 (100%)

Time: 00:01.298, Memory: 48.00 MB

OK (34 tests, 142 assertions)
```

---

## 🤝 Contributing

Contributions, bug reports, and pull requests are welcome on GitHub at [mixudev/package_LaravelSecurityDefense](https://github.com/mixudev/package_LaravelSecurityDefense).

---

## 📄 License

The MIT License (MIT). Please see [License File](LICENSE) for more information.
