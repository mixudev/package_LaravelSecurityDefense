# Security Audit Report — mixudev/security-defense

Audit status: staged white-box audit + targeted remediation
Audit date: 2026-09-11
Scope: `src/`, `routes/`, `config/`, `resources/views/`, `tests/`, provider wiring, WAF, channels, dashboard, opaque path, epistemic opt-in subsystem

## Current verification

- PHPUnit baseline before remediation: `377 tests, 1126 assertions` — pass.
- PHPUnit after staged remediation: `384 tests, 1163 assertions` — pass.
- Focused WAF/regression batch: `15 tests, 79 assertions` — pass.
- Focused channel/detection batch: `13 tests, 40 assertions` — pass.
- Focused channel/config batch: `24 tests, 80 assertions` — pass.
- Focused formatter/channel batch: `11 tests, 33 assertions` — pass.
- Focused dashboard/epistemic batch: `18 tests, 51 assertions` — pass.
- PHP lint on changed PHP files: pass.
- `git diff --check`: pass.
- PHPStan: unavailable; static-analysis status UNVERIFIED.
- True multi-process Redis/Memcached concurrency: not exercised; status UNVERIFIED.
- Consumer playground integration: not exercised in this staged batch.

## Executive summary

Package has strong defensive coverage and broad adversarial tests. Dashboard gateway, opaque path resolution, CSRF coverage, response headers, payload signatures, metadata bounds, queue channel allowlist, and opt-in epistemic response behavior are materially protected.

Package is not fully silent by default. Provider loads routes/views/migrations; dashboard routes remain registered when the master engine switch is false; core detection/quarantine config defaults are enabled but preventive WAF middleware requires explicit host registration. External Telegram, Discord, and interactive bot effects are now opt-in by default.

Staged remediation fixed confirmed issues in raw-body detection parity, SSRF private-range matching, raw-body decode bounds, counter-window initialization, distributed-spray identifier persistence, webhook HMAC body integrity, Telegram webhook constant-time secret comparison, external-channel defaults, Telegram Markdown code-field handling, webhook log redaction, and epistemic dashboard cache-store/key alignment.

## Confirmed findings and status

| ID | Severity | Finding | Status | Location |
|---|---:|---|---|---|
| WAF-001 | HIGH | `has()` + `put(counter, 0)` could reset atomic counters under concurrency | FIXED | `src/Rules/BruteForceRule.php`, `BehavioralVelocityRule.php`, `PathReconnaissanceRule.php`, `RateLimitBypassRule.php`, `src/Services/RequestFloodLimiter.php` |
| WAF-003 | HIGH | Detector event path omitted `metadata.raw_content` | FIXED | `src/Rules/PayloadInjectionRule.php` |
| WAF-004 | HIGH | Raw body decoded before inspection-length bound | FIXED | `src/Services/PayloadDecoder.php` |
| WAF-006 | MEDIUM | SSRF regex used five-octet `192.168` pattern | FIXED | `src/Rules/PayloadInjectionRule.php` |
| WAF-008 | MEDIUM | Distributed spray persisted target identifier plaintext | FIXED | `src/Rules/DistributedSprayRule.php` |
| WAF-012 | HIGH | Cache-only quarantine is bypassable after cache loss when DB persistence disabled | OPEN / DOCUMENTED | `src/Services/IpQuarantineService.php`, `config/security-defense.php` |
| SD-001 | MEDIUM | Request host can enter telemetry URL under unsafe proxy configuration | FIXED | `src/Support/RequestLocationRedactor.php`, `src/Services/DataAuditService.php` |
| SD-002 | LOW | Master `security-defense.enabled` does not suppress route registration | OPEN / CONTRACT DECISION | `routes/web.php` |
| SD-003 | LOW | Dashboard path has no reserved webhook namespace validation | OPEN | `routes/web.php` |
| CH-001 | HIGH | Webhook signature was computed over JSON different from actual request encoding | FIXED | `src/Channels/WebhookChannel.php` |
| CH-002 | MEDIUM | Webhook failure logs could expose query credentials and exception internals | FIXED | `src/Channels/WebhookChannel.php` |
| CH-003 | MEDIUM | Telegram dynamic code fields could close/alter Markdown spans | FIXED | `src/Support/TelegramAlertFormatter.php` |
| CH-004 | MEDIUM | Telegram webhook secret used ordinary comparison | FIXED | `src/Http/Controllers/TelegramWebhookController.php` |
| CH-005 | LOW | Telegram/Discord/interactive bot defaults caused optional external effects when credentials existed | FIXED | `config/security-defense.php` |
| Q-001 | MEDIUM | Concurrent `jail()` and `pardon()` can leave stale quarantine state | FIXED WITH PER-IP CACHE LOCK | `src/Services/IpQuarantineService.php` |
| Q-002 | HIGH | DB persistence and fail-closed quarantine are opt-in | OPEN / DOCUMENTED | `config/security-defense.php:284-287` |
| EP-001 | HIGH | Analyzer snapshot key/store differed from dashboard reader | FIXED | `src/Epistemic/EpistemicAnalyzer.php`, `src/Http/Controllers/DashboardController.php` |
| EP-002 | MEDIUM | Snapshot is one global key and concurrent analyses overwrite each other | OPEN | `src/Epistemic/EpistemicAnalyzer.php` |
| EP-003 | MEDIUM | Normal `processEvent()` path does not automatically call epistemic analysis | OPEN / OPT-IN CONTRACT | `src/Services/SecurityDefenseManager.php` |
| EP-004 | MEDIUM | Dashboard feedback key does not prove analyzer memory-key compatibility | OPEN | `src/Http/Controllers/DashboardController.php`, `src/Epistemic/Memory/ExperienceMemory.php` |
| EP-005 | MEDIUM | Response adapter retries after exception and can duplicate side effect | FIXED — single attempt | `src/Epistemic/EpistemicAnalyzer.php` |
| EP-006 | HIGH | Memory fallback read-modify-write can lose updates without cache locks | OPEN / DRIVER DEPENDENT | `src/Epistemic/Memory/ExperienceMemory.php` |

## Silent ecosystem assessment

| Surface | Default behavior | Assessment |
|---|---|---|
| Provider bindings | Registered at package boot | Expected package boot effect |
| Routes | Dashboard routes load when `dashboard.enabled=true`, independent of master engine switch | Not fully silent; low exposure with gateway |
| WAF middleware | Host must register `RequestThreatScanner` | Silent until explicit host registration |
| Database migrations | Loaded by provider; host runs migration command | Expected install-time effect |
| Database alert channel | Enabled by default | Writes only when telemetry reaches dispatcher |
| Telegram/Discord/webhook/mail | Telegram/Discord now false; webhook/mail false | No external channel request by default |
| Epistemic analysis | Disabled by default | No normal runtime epistemic analysis by default |
| Epistemic response adapter | Disabled + no-op fallback | No autonomous response by default |
| Cache namespace | Configurable prefix; default package prefix | Host must provide unique prefix when sharing cache |
| Config overrides | Package-owned override path | Must remain writable only when operator enables dashboard mutation |

Conclusion: package does not silently inject global WAF middleware, but package installation still adds provider work, routes, views, migration loading, and default internal detection configuration. Public exposure remains dependent on host middleware/policy configuration.

## Positive controls verified

- Dashboard route group uses `EnsureLocalAccess`.
- Public dashboard mode requires network allowlist, authentication, Gate, and optional step-up.
- Opaque path is environment-backed, bounded, route-cache-aware, and relative-redirect based.
- CSRF present on dashboard mutation forms.
- WAF scans raw content through middleware and detector parity now includes `raw_content`.
- Raw body is bounded before decode; final scan values are bounded before regex.
- Detection counters use atomic `add` seed + `increment` pattern in staged fixed rules.
- Alert metadata recursively trims strings and enforces global JSON byte bound.
- Queue alert channel class is allowlisted.
- Credential-stuffing identifiers and distributed-spray IP samples are hashed; distributed target identifier is now hashed.
- Webhook HMAC covers exact raw JSON body sent.
- Telegram webhook secret uses `hash_equals`.
- External Telegram/Discord/interactive bot features are opt-in by default.
- Epistemic response adapter remains opt-in and no-op by default.
- Focused adversarial and rendering tests pass with populated data.

## Open risks and required decisions

1. Enable durable DB quarantine and `db_fail_closed=true` for production deployments where cache loss must not release an attacker. This adds migration/DB dependency.
2. Require a trusted proxy contract before treating `Request::ip()` or host-derived URLs as security identity/location.
3. Decide whether `security-defense.enabled=false` must remove dashboard route registration or only disable engines. Changing route behavior may affect backward compatibility.
4. Add reserved route-segment validation for dashboard path before accepting arbitrary host configuration.
5. Add lock/transaction semantics around `jail()` and `pardon()` after a real locking-cache integration test exists.
6. Replace global epistemic snapshot with subject/assessment identity or explicitly document “latest assessment only”; protect writes with version/claim semantics if response is enabled.
7. Wire or explicitly preserve the opt-in boundary for normal event → epistemic analysis. A tested class is not automatically active protection.
8. Align feedback memory keys with analyzer recall keys and add an end-to-end feedback-affects-next-assessment test.
9. Replace response retry-after-side-effect with an explicit idempotent adapter contract.
10. Install PHPStan or equivalent static analysis in CI; current static-analysis result is UNVERIFIED.
11. Run consumer playground tests and multi-worker Redis/Memcached tests before production-readiness claim.

## Modularization governance

Line count is review signal, not deletion rule. Keep cohesive config and domain files together. Split only at responsibility boundaries and preserve public API through delegation.

| File | Lines | Responsibility collision | Planned action |
|---|---:|---|---|
| `src/Http/Controllers/DashboardController.php` | 444 | views, feedback, channel probe, mutations, query orchestration | Split into dashboard view/query controller, feedback controller, channel probe controller, mutation controller; preserve route names and response contracts |
| `src/Console/Commands/AuthSyncCommand.php` | 397 | event mapping, code generation, file injection | Extract mapping and generated-source builder; keep command output/exit codes |
| `src/Epistemic/EpistemicAnalyzer.php` | 294 | evidence admission, graph, memory, response, snapshot publishing | Extract bounded collaborators only after characterization tests; keep analyzer facade |
| `src/Providers/SecurityDefenseServiceProvider.php` | 295 | config override, bindings, boot/console registration | Extract binding registration helpers only if container tests stay green |
| `src/Services/DataAuditService.php` | 290 | audit normalization, persistence, tamper analysis, alerting | Review responsibility boundaries before split; no blind line split |
| `src/Services/IpQuarantineService.php` | 289 | policy, cache, DB persistence, config mutation | Extract persistence adapter only with cache/DB parity tests |
| `resources/views/epistemic.blade.php` | 263 | page shell, charts, evidence, feedback | Split includes after populated render tests; preserve CSRF and escaping |
| `src/Services/TelegramBotService.php` | 322 | orchestration, authorization, command handling | Extract command authorization/dispatcher after behavior characterization |

No broad modularization performed yet. Security fixes remain separate from future refactor commits.

## Test gaps

- Multi-process race tests against Redis/Memcached.
- Cache flush/restart quarantine behavior with production-like stores.
- Concurrent `jail()`/`pardon()` final-state test.
- Webhook SSRF destination validation and redirect policy.
- Telegram poller single-consumer/duplicate update behavior.
- Queue retry/idempotency behavior for transient channel failures.
- Epistemic feedback → memory → next assessment integration.
- Epistemic response adapter idempotency and side-effect failure behavior.
- Consumer application (`D:/WEBSITE/PLAYGROUND/LARAVEL-TESTING`) verification.

## Staged changes in current worktree

No commit or push performed. Changes are intentionally left for review.
