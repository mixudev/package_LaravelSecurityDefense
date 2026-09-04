# Laravel Security Defense (`mixudev/security-defense`)

[![Tests](https://img.shields.io/badge/tests-34%20passed-brightgreen.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PHP Version](https://img.shields.io/badge/PHP-%5E8.2-blue.svg)]()
[![Laravel Support](https://img.shields.io/badge/Laravel-10%20%7C%2011%20%7C%2012%20%7C%2013-red.svg)]()

An enterprise-grade, modular, and configurable security defense package for Laravel applications. Designed as an intelligent **"security camera and proactive shield"** (telemetry correlation, multi-vector threat scoring, automated IP quarantine, deduplicated alerting, and preventive WAF payload scanning) without duplicating or coupling to specific authentication systems.

---

## Core Principle

> **"Authentication is the gatekeeper. Security Defense is the security camera and proactive shield."**

`mixudev/security-defense` **does not duplicate authentication features**. It does not provide user management, password hashing, session tokens, audit logs, captchas, or custom rate-limiter replacements. Instead, it consumes security telemetry emitted by your application and detects multi-request attack patterns, manages deduplicated alerts across multiple channels, and blocks dangerous payloads before reaching controllers.

---

## Enterprise-Grade Capabilities

- **Generic ThreatSource Abstraction**: Ingest security events from any authentication system (Fortify, Breeze, Sanctum, custom JWT) without hardcoded dependencies.
- **Stateless Anomaly Detection Engine (8 Rules)**:
  - `BruteForceRule`: Sliding-window detection of repeated failed attempts on a single account.
  - `CredentialStuffingRule`: Probing multiple distinct accounts from a single IP.
  - `DistributedSprayRule`: Probing a single account across multiple distinct IPs.
  - `RateLimitBypassRule`: Proxy chain manipulation (`X-Forwarded-For`) and rapid IP cycling.
  - `PayloadInjectionRule`: SQL Injection, XSS, Path Traversal, and OS Command Injection detection.
  - `ImpossibleTravelRule`: Physical velocity check (Haversine formula) between successive logins.
  - `PathReconnaissanceRule`: Reconnaissance scans targeting sensitive files (`.env`, `.git`, `wp-admin`, database dumps).
  - `UserAgentAnomalyRule`: Hostile automated scanner fingerprinting (`sqlmap`, `nikto`, `dirbuster`, `gobuster`, etc.).
- **Compound Threat Scoring Engine**: Correlates multiple attack vectors across a sliding window per entity, auto-escalating to `CRITICAL` compound threats when cumulative risk exceeds the configured threshold.
- **Active IP Quarantine (Fail2Ban-Style Defense)**: Automatically or manually isolates malicious IPs in cache, instantly blocking subsequent requests (HTTP 429) at the very start of middleware with **zero CPU regex overhead**.
- **Self-Defense & Zero Vulnerability Guarantees**:
  - Anti-ReDoS string length truncation (`max_inspection_length`).
  - Anti-Memory Exhaustion recursion limit (`max_traversal_depth`).
  - Anti-Disk Exhaustion database alert rate limiter.
  - Automatic recursive credential masking (`Sanitizer`).
- **Multi-Channel Alert Dispatcher (Sync or Queued)**:
  - `DatabaseChannel`: Mandatory persistence into `security_alerts` table.
  - `TelegramChannel`: Fail-safe Markdown notifications via Telegram Bot API.
  - `DiscordChannel`: Fail-safe rich embed notifications.
  - `WebhookChannel`: SIEM/central dashboard notifications with HMAC SHA-256 signatures.
  - **Background Queue Support (`ShouldQueue`)**: Offload external notifications to Laravel queues for zero request latency overhead.

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

### 3. Managing IP Quarantine Programmatically

```php
use Mixudev\SecurityDefense\Support\Facades\SecurityDefense;

// Check quarantine status
$jailed = SecurityDefense::quarantine()->isQuarantined('198.51.100.5');

// Jail IP for 30 minutes
SecurityDefense::quarantine()->jail('198.51.100.5', 1800, 'Suspicious port scanning');

// Release IP from quarantine
SecurityDefense::quarantine()->pardon('198.51.100.5');
```

---

## AI Living Documentation

Complete technical documentation, ADRs, and architectural guides are maintained in `docs/ai/`:

- [README.md](docs/ai/README.md) - Documentation Index
- [ARCHITECTURE.md](docs/ai/ARCHITECTURE.md) - Architectural model and data flow
- [DECISIONS.md](docs/ai/DECISIONS.md) - Architecture Decision Records (ADRs 001 - 009)
- [IMPLEMENTATION.md](docs/ai/IMPLEMENTATION.md) - Component and class details
- [SECURITY.md](docs/ai/SECURITY.md) - Self-defense, DoS mitigations, and zero-leakage guarantees
- [CONFIGURATION.md](docs/ai/CONFIGURATION.md) - Full configuration reference
- [INTEGRATION.md](docs/ai/INTEGRATION.md) - Integration guides for auth, quarantine, and queues
- [TESTING.md](docs/ai/TESTING.md) - Test strategy and verification results (34/34 passing)
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
