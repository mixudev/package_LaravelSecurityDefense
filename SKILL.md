---
name: laravel-security-defense
description: "Install, harden, and operate mixudev/security-defense."
version: 1.10.1
author: MixuDev, Hermes Agent
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [laravel, security, waf, fail2ban, siem, 2fa, otp]
    related_skills: [security-audit, identity-platform-development]
---

# Laravel Security Defense (`mixudev/security-defense`)

Procedural runbook for AI agents installing, wiring, configuring, and verifying the `mixudev/security-defense` package on any Laravel 10 / 11 / 12 / 13 application.

## When to Use

- Installing `mixudev/security-defense` into a fresh or existing Laravel application.
- Wiring WAF middleware, auto-watch Eloquent data audit, or 2FA dashboard OTP.
- Hardening an application against DDoS/flood, parameter tampering (Burp), session hijacking, or credential stuffing.
- Exposing the security dashboard locally or safely over public networks.
- Setting up multi-channel alerting (Telegram, Discord, Webhook, Email).

## Prerequisites

- PHP `^8.2` with `openssl`, `mbstring`, `pdo`, and `json` extensions.
- Laravel `^10.0`, `^11.0`, `^12.0`, or `^13.0`.
- Cache driver running (Redis or Memcached strongly recommended for production multi-worker concurrency; `file` or `array` supported for local).
- Database connection configured and migrated (`DB_CONNECTION`).

## Canonical Quick Reference

```bash
# 1. Composer require
composer require mixudev/security-defense

# 2. Automated installer (publishes config, migrates tables, registers opaque path, clears caches)
php artisan security-defense:install --with-opaque-path

# 3. Synchronize WAF middleware and auth subscriber
php artisan security-defense:auth:sync

# 4. Verify deployment
php artisan route:list --name=security-defense
```

---

## Complete Step-by-Step Installation Procedure

Follow every numbered step. Every step has a verifiable completion criterion.

### Step 1: Install Composer Dependency

Inside the target host application root:

```bash
composer require mixudev/security-defense:^1.10.1
```

*Verification*: Check `composer.json` contains `"mixudev/security-defense"` in `require`, and `vendor/mixudev/security-defense` exists on disk.

### Step 2: Run Package Installer

```bash
php artisan security-defense:install --with-opaque-path
```

This automated command executes:
1. `vendor:publish --tag=security-defense-config` (places `config/security-defense.php`).
2. Enables capability-gated dashboard (`dashboard.opaque_path.enabled = true`).
3. Runs database migrations:
   - `security_alerts` (SIEM alert records)
   - `security_quarantines` (Fail2Ban IP blocklist)
   - `security_data_audits` (Eloquent mutation & tamper logs)
   - `epistemic_threat_patterns` (probabilistic threat memory)
4. Rebuilds route and config caches.

*Manual fallback* (if artisan install is skipped):
```bash
php artisan vendor:publish --tag=security-defense-config
php artisan migrate
```

### Step 3: Register WAF Middleware in Host Application

The Preventive WAF middleware (`RequestThreatScanner`) must sit on the global or web middleware stack.

#### Laravel 11 / 12 / 13 (`bootstrap/app.php`)

```php
use Mixudev\SecurityDefense\Middleware\RequestThreatScanner;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware) {
        // Append to global stack (recommended for full WAF coverage)
        $middleware->append(RequestThreatScanner::class);

        // Optional: CSP Armor (neutralizes inline scripts/XSS)
        // $middleware->append(\Mixudev\SecurityDefense\Middleware\ContentSecurityPolicyArmor::class);
    })
    ->withExceptions(function (Exceptions $exceptions) {
        //
    })->create();
```

#### Laravel 10 (`app/Http/Kernel.php`)

Add to `protected $middleware`:
```php
protected $middleware = [
    // ...
    \Mixudev\SecurityDefense\Middleware\RequestThreatScanner::class,
];
```

*Verification*:
```bash
php artisan security-defense:auth:sync --dry-run
```
Output must print: `[OK] WAF middleware already registered`.

### Step 4: Wire Session Intelligence & Data Audit

#### 4a. Authenticated Session Scanner (Session Hijacking & Infostealer Defense)
Register in `bootstrap/app.php` inside `$middleware->web(...)`:
```php
$middleware->web(append: [
    \Mixudev\SecurityDefense\Middleware\AuthenticatedSessionScanner::class,
]);
```

#### 4b. Auto-Watch Sensitive Eloquent Models (Burp Parameter Tampering Detection)
Open `config/security-defense.php` and declare critical models in `data_audit.auto_watch_models`:
```php
'data_audit' => [
    'enabled' => true,
    'queue' => [
        'enabled' => true, // Dispatch snapshot logging via async queue under load
    ],
    'auto_watch_models' => [
        \App\Models\User::class,
        // \App\Models\Order::class,
        // \App\Models\Payment::class,
    ],
],
```
When an attacker modifies a guarded field (e.g. `role`, `is_admin`, `balance`) via Burp Suite, the package detects the mutation, verifies against the original payload snapshot, flags `is_tampered = true`, and raises a SIEM alert.

### Step 5: Configure Environment Variables (`.env`)

Add the following block to the host application's `.env`:

```env
# ==============================================================================
# Security Defense Configuration
# ==============================================================================
SECURITY_DEFENSE_ENABLED=true

# Cache Store: redis or memcached strongly advised in multi-server production
# SECURITY_DEFENSE_CACHE_STORE=redis

# Dedicated Dashboard Key (optional; falls back to APP_KEY via HKDF derivation)
# SECURITY_DEFENSE_KEY=

# Dashboard Second-Factor (OTP) - Default: false
SECURITY_DEFENSE_OTP_ENABLED=false
SECURITY_DEFENSE_OTP_CHANNEL=email
SECURITY_DEFENSE_OTP_EMAIL=security-admin@yourdomain.com
SECURITY_DEFENSE_OTP_TTL=300

# Outbound Alert Channels (configure at least one)
# Telegram:
SECURITY_DEFENSE_TELEGRAM_ENABLED=false
SECURITY_DEFENSE_TELEGRAM_BOT_TOKEN=
SECURITY_DEFENSE_TELEGRAM_CHAT_ID=

# Discord:
SECURITY_DEFENSE_DISCORD_ENABLED=false
SECURITY_DEFENSE_DISCORD_WEBHOOK_URL=

# Generic Webhook (HMAC-SHA256 signed):
SECURITY_DEFENSE_WEBHOOK_ENABLED=false
SECURITY_DEFENSE_WEBHOOK_URL=
SECURITY_DEFENSE_WEBHOOK_SECRET=

# Email Alerts:
SECURITY_DEFENSE_MAIL_ENABLED=false
SECURITY_DEFENSE_MAIL_TO=alerts@yourdomain.com
```

### Step 6: Configure Dashboard Access Policy

Default is **Local Only** (`local_only => true`, IPs `127.0.0.1`, `::1`).

#### To expose the dashboard safely in Staging or Production:

In `config/security-defense.php`:

```php
'dashboard' => [
    'enabled' => true,
    'path' => 'security-defense',
    'local_only' => false, // Set false for remote/public access

    // Trusted proxies boundary: NEVER set to '*' in production.
    // List your ingress reverse proxies (Cloudflare, AWS ALB, Nginx).
    'trusted_proxies' => [
        '127.0.0.1',
        '::1',
        // '10.0.0.0/8',
    ],

    'public' => [
        'enabled' => true,
        'authorization_gate' => 'viewSecurityDefenseDashboard',
        'require_authenticated_user' => true,
        'require_step_up' => false,
        'allowed_ips' => [
            // '203.0.113.10', // Operator static IP
        ],
        'allowed_cidrs' => [
            // '198.51.100.0/24', // Corporate VPN range
        ],
    ],

    // Enable 2FA OTP for remote dashboard access
    'otp' => [
        'enabled' => true,
        'channel' => 'email', // or 'telegram'
        'email' => 'operator@yourdomain.com',
    ],
],
```

Define the authorization Gate in `app/Providers/AppServiceProvider.php`:
```php
use Illuminate\Support\Facades\Gate;

public function boot(): void
{
    Gate::define('viewSecurityDefenseDashboard', function ($user) {
        return (bool) ($user->is_admin ?? false);
    });
}
```

### Step 7: Schedule Stale Records Pruning

In `routes/console.php` (Laravel 11+) or `app/Console/Kernel.php` (Laravel 10):

```php
use Illuminate\Support\Facades\Schedule;

// Prunes normal audits >30d, tampered forensic evidence >90d, alerts >60d
Schedule::command('security-defense:prune')->dailyAt('02:00');
```

---

## Verification & Self-Check Runbook

Execute these commands from terminal to prove 100% functionality:

### Check 1: Route Registration
```bash
php artisan route:list --name=security-defense
```
Must display:
- `GET|HEAD security-defense` -> `portal.index`
- `POST security-defense/enter` -> `portal.enter`
- `GET|HEAD security-defense/verify-code` -> `portal.otp-form`
- `POST security-defense/verify-code` -> `portal.verify-otp`
- `GET|HEAD security-defense/{opaque}` -> `security-defense.dashboard`
- Sub-routes for `data-audits`, `sessions`, `epistemic`, `live-events`.

### Check 2: Outbound Alert Channel Connectivity
```bash
# Probes configured channels with a signed benign test alert
php artisan security-defense:test-webhook
```

### Check 3: Active WAF Blocking Test
Send a benign SQLi probe to any route wrapped with the middleware:
```bash
curl -i -X POST http://127.0.0.1:8000/ -d "probe=1' OR 1=1--"
```
Expected HTTP response: `403 Forbidden` with body `{"error": "Security violation detected."}`.

### Check 4: Fail2Ban Quarantine Verification
Inspect database quarantine table:
```bash
php artisan tinker --execute="echo Mixudev\SecurityDefense\Models\SecurityQuarantine::count();"
```
Or view the active jail list via the dashboard: `http://127.0.0.1:8000/security-defense`.

---

## Known Pitfalls & Solutions

1. **`Method_exists($cache, 'lock')` trap**:
   Always use `Mixudev\SecurityDefense\Support\CacheLock::run()` or `reserveSlot()`. Do not call `$cache->lock()` directly behind `method_exists()` because `Illuminate\Cache\Repository` proxies locks via `__call()`.

2. **Wildcard `trustProxies = ['*']`**:
   Never trust `*` proxies in production. An untrusted peer can rotate `X-Forwarded-For` to bypass IP quarantine. Define explicit CIDRs or rely on socket `REMOTE_ADDR`.

3. **`ArrayStore` / cache counter TTL**:
   Always seed TTL using `$cache->add($key, 0, $ttl)` *before* calling `$cache->increment($key)`. Calling `increment()` first causes Laravel's `ArrayStore` to mark the key `forever()`, rendering the subsequent `add()` a no-op.

4. **Queue worker not running**:
   If `data_audit.queue.enabled = true` or `alerts.queue.enabled = true`, ensure `php artisan queue:work` is active, otherwise telemetry snapshots and email/webhook dispatches will queue indefinitely.

5. **Local dashboard access returns 403**:
   If accessing via `localhost` instead of `127.0.0.1`, IPv6 loopback (`::1`) must be present in `dashboard.allowed_ips` (included by default).
