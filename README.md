# Laravel Security Defense (`mixudev/security-defense`)

[![Tests](https://img.shields.io/badge/tests-25%20passed-brightgreen.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PHP Version](https://img.shields.io/badge/PHP-%5E8.2-blue.svg)]()
[![Laravel Support](https://img.shields.io/badge/Laravel-10%20%7C%2011%20%7C%2012-red.svg)]()

A modular, reusable, and configurable security defense package for Laravel applications. Designed as an intelligent **"security camera"** (telemetry consumption, correlation, anomaly detection, deduplicated alerting, and preventive payload scanning) without duplicating or coupling to specific authentication systems.

---

## Core Principle

> **"Authentication is the gatekeeper. Security Defense is the security camera."**

`mixudev/security-defense` **does not duplicate authentication features**. It does not provide user management, password hashing, session tokens, audit logs, captchas, or custom rate-limiter replacements. Instead, it consumes security telemetry emitted by your application and detects multi-request attack patterns, manages deduplicated alerts across multiple channels, and blocks dangerous payloads before reaching controllers.

---

## Features

- **Generic ThreatSource Abstraction**: Ingest security events from any authentication system (Fortify, Breeze, Sanctum, custom JWT) without hardcoded dependencies.
- **Stateless Anomaly Detection Engine**:
  - `BruteForceRule`: Sliding-window detection of repeated failed attempts on a single account.
  - `CredentialStuffingRule`: Probing multiple distinct accounts from a single IP.
  - `DistributedSprayRule`: Probing a single account across multiple distinct IPs.
  - `RateLimitBypassRule`: Proxy chain manipulation (`X-Forwarded-For`) and rapid IP cycling.
  - `PayloadInjectionRule`: SQL Injection, XSS, Path Traversal, and OS Command Injection detection.
  - `ImpossibleTravelRule`: Physical velocity check (Haversine formula) between successive logins.
- **Alert Deduplication Subsystem**: Suppresses alert storms using SHA-256 fingerprint caching within a configurable time window.
- **Multi-Channel Alert Dispatcher**:
  - `DatabaseChannel`: Mandatory persistence into `security_alerts` table.
  - `TelegramChannel`: Fail-safe Markdown notifications via Telegram Bot API.
  - `DiscordChannel`: Fail-safe rich embed notifications.
  - `WebhookChannel`: SIEM/central dashboard notifications with optional HMAC SHA-256 signatures.
- **Active Preventive Middleware**:
  - `RequestThreatScanner`: WAF-level pre-controller payload inspection that blocks malicious requests (HTTP 403) and logs safe, sanitized telemetry.
- **Strict Data Privacy**:
  - Built-in recursive `Sanitizer` guarantees passwords, tokens, API keys, and authorization headers are never persisted or transmitted.

---

## Installation

```bash
composer require mixudev/security-defense
```

Publish configuration and migrations:

```bash
php artisan vendor:publish --provider="Mixudev\SecurityDefense\Providers\SecurityDefenseServiceProvider"
php artisan migrate
```

---

## Quick Usage

### 1. Feeding Telemetry Events

You can feed telemetry into the defense engine using arrays or the `SecurityDefense` Facade:

```php
use Mixudev\SecurityDefense\Support\Facades\SecurityDefense;

SecurityDefense::record([
    'ip' => request()->ip(),
    'identifier' => $request->input('email'),
    'eventType' => 'LoginFailed',
    'timestamp' => now()->toIso8601String(),
    'userAgent' => request()->userAgent(),
    'metadata' => [
        'form' => 'admin_login',
    ],
]);
```

### 2. Preventive WAF Middleware

Add `RequestThreatScanner` to your web or API routes:

```php
// bootstrap/app.php (Laravel 11+)
->withMiddleware(function (Middleware $middleware) {
    $middleware->append(\Mixudev\SecurityDefense\Middleware\RequestThreatScanner::class);
})
```

---

## AI Living Documentation

Complete technical documentation, ADRs, and architectural guides are maintained in `docs/ai/`:

- [README.md](docs/ai/README.md) - Documentation Index
- [ARCHITECTURE.md](docs/ai/ARCHITECTURE.md) - Architectural model and data flow
- [DECISIONS.md](docs/ai/DECISIONS.md) - Architecture Decision Records (ADR)
- [IMPLEMENTATION.md](docs/ai/IMPLEMENTATION.md) - Component and class details
- [SECURITY.md](docs/ai/SECURITY.md) - Data privacy and zero-leakage guarantees
- [CONFIGURATION.md](docs/ai/CONFIGURATION.md) - Full configuration reference
- [INTEGRATION.md](docs/ai/INTEGRATION.md) - Integration guides for auth, channels, and middleware
- [TESTING.md](docs/ai/TESTING.md) - Test strategy and verification results
- [CHANGELOG.md](docs/ai/CHANGELOG.md) - Version history
- [TODO.md](docs/ai/TODO.md) - Development roadmap status

---

## Testing

```bash
composer test
```

---

## License

The MIT License (MIT). Please see [License File](LICENSE) for more information.
