# Testing Strategy — `mixudev/security-defense`

Validasi release mencakup kontrak package, integrasi Laravel, dan unit service.

## Environment

- PHPUnit `12.x` dari `composer.json`
- Orchestra Testbench `^8.0|^9.0|^10.0|^11.0`
- SQLite in-memory database
- Array cache default; cache store lain diuji eksplisit

## Menjalankan test

```bash
vendor/bin/phpunit
composer test
```

Baseline HEAD: **311 tests, 948 assertions**. Output PHPUnit tetap sumber kebenaran.

## Struktur test

```text
tests/
├── Feature/
│   └── Epistemic/
└── Unit/
    └── Epistemic/
```

- `tests/Feature/` — kontrak package, middleware, dashboard, audit, queue, command, telemetry, integrasi epistemic.
- `tests/Feature/Epistemic/` — `EpistemicAnalyzerTest.php`, `EpistemicBackwardCompatibilityTest.php`.
- `tests/Unit/` — channel, dispatcher, rules, sanitizer, scoring, service, event, regression security.
- `tests/Unit/Epistemic/` — value objects, evidence, engine, graph, policy, memory, feedback, correlation, response boundary.
- `tests/TestCase.php` — base test case.

## Cakupan kontrak penting

`IntegrationReleaseContractsTest` memverifikasi migrasi, config boot, cache-store isolation, binding epistemic saat enabled/disabled, dan kewajiban registrasi middleware WAF oleh host app. Test epistemic juga memverifikasi batas evidence, feedback outcome, AI advisory, policy, response adapter, dan backward compatibility.

`epistemic_threat_patterns` adalah schema migrasi yang belum dipakai sebagai repository. `ExperienceMemory` menyimpan pola pada cache. Jangan mengklaim persistence database tanpa perubahan desain.

## Checklist validasi

```bash
vendor/bin/phpunit
find src tests database config routes -name '*.php' -print0 | xargs -0 -n1 php -l
git diff --check
```

PHPStan bukan dependency package. Markdown lint tidak tersedia di environment ini.
