# Testing Strategy — `mixudev/security-defense`

Release validation targets package contracts, not only isolated service behavior.

## Environment

- PHPUnit `11.5.56`
- Orchestra Testbench `10.11.0` (Laravel 12 lock)
- SQLite in-memory database
- Array cache by default; dedicated stores tested explicitly

Run:

```bash
vendor/bin/phpunit
composer test
```

## Current coverage

Current baseline before release-contract additions: **286 tests, 863 assertions**. Do not copy a test total from this document after adding or removing tests; use PHPUnit output as source of truth.

`tests/Feature/IntegrationReleaseContractsTest.php` covers:

- SQLite migration `up` creation and `down` rollback for all package migrations.
- Default config boot and cached-config-compatible provider defaults.
- `security-defense.cache_store` isolation for `AlertDispatcher`, `ExperienceMemory`, and `IpQuarantineService`.
- Epistemic provider bindings when feature disabled/enabled.
- Manual host registration requirement for WAF middleware; package does not auto-register middleware aliases.

Existing unit and feature tests cover sanitization, detection rules, threat scoring, alert channels, queue dispatch, middleware behavior, dashboard flows, telemetry, and epistemic components.

## Schema note

`epistemic_threat_patterns` migration is currently dead schema: `ExperienceMemory` persists patterns in configured cache and has no model or database repository path. Tests verify migration rollback only. Do not infer DB persistence from this table or wire DB persistence without an explicit design change.

## Validation checklist

```bash
vendor/bin/phpunit
find src tests database config routes -name '*.php' -print0 | xargs -0 -n1 php -l
git diff --check
```

PHPStan is not part of local validation when unavailable. Composer validation remains environment-dependent if local Composer phar path is broken.
