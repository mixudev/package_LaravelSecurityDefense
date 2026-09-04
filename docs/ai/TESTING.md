# Testing Strategy & Validation — `mixudev/security-defense`

Dokumen ini mencatat rencana pengujian, jenis test yang dijalankan, dan validasi seluruh scenario package.

---

## 1. Lingkungan & Setup Pengujian

- **Test Framework**: PHPUnit `11.5.56`
- **Laravel Testbench**: `orchestra/testbench` `10.11.0` (Laravel 12 Support)
- **Database Driver**: SQLite in-memory (`:memory:`)
- **Cache Driver**: Array Cache Store

Menjalankan pengujian:

```bash
vendor/bin/phpunit
# atau via composer script
composer test
```

---

## 2. Rincian Test Cases yang Dijalankan

Total: **25 tests, 90 assertions, 0 failures, 100% passing.**

### A. Sanitizer & DTO Unit Tests
- `tests/Unit/SanitizerTest.php`:
  - `test_it_redacts_sensitive_keys_recursively`: Memvalidasi masking `[REDACTED]` pada keys seperti `password`, `token`, `bot_token`, `credit_card`, `cvv`, `authorization`, baik pada level atas maupun nested array.
  - `test_it_scrubs_bearer_tokens_inside_strings`: Memverifikasi pembersihan string Bearer token dari headers/payload.
- `tests/Unit/SecurityEventTest.php`:
  - `test_it_instantiates_and_sanitizes_metadata`: Memvalidasi immutable DTO dan sanitasi instan saat konstruksi.
  - `test_from_array_factory`: Memverifikasi factory method `fromArray()` dari array raw input.
- `tests/Unit/SecurityThreatTest.php`:
  - `test_it_creates_threat_with_sanitized_metadata_and_deterministic_fingerprint`: Memvalidasi perhitungan SHA-256 fingerprint deterministik.
  - `test_it_normalizes_invalid_severity_to_medium`: Memvalidasi fallback severity jika diberikan nilai di luar `low|medium|high|critical`.

### B. Detection Rules Unit Tests (`tests/Unit/DetectionRulesTest.php`)
- `test_brute_force_rule_detects_repeated_failed_attempts`: Menguji toleransi sebelum threshold dan pelaporan ancaman tepat saat mencapai threshold.
- `test_credential_stuffing_rule_detects_multiple_accounts_from_one_ip`: Memvalidasi deteksi multiple account probe dari satu IP.
- `test_distributed_spray_rule_detects_multiple_ips_targeting_single_account`: Memvalidasi pelaporan distributed password spray ke satu username target.
- `test_rate_limit_bypass_rule_detects_proxy_spoofing`: Memverifikasi deteksi proxy chain header spoofing pada `X-Forwarded-For`.
- `test_payload_injection_rule_detects_sqli_and_xss`: Memverifikasi deteksi SQLi (`UNION SELECT`, `' OR 1=1`) dan XSS script tags.
- `test_impossible_travel_rule_detects_excessive_speed`: Memverifikasi rumus Haversine jarak Jakarta -> London dalam selang 1 detik menghasilkan speed > 900 km/jam dan memicu alert impossible travel.

### C. Alert Deduplication Unit Tests (`tests/Unit/AlertDeduplicatorTest.php`)
- `test_it_deduplicates_identical_threat_fingerprints`:
  - Ancaman pertama: `shouldAlert` mengembalikan `true`.
  - Setelah `record()`: `shouldAlert` dengan fingerprint sama mengembalikan `false` (suppressed).
  - Setelah `forget()`: `shouldAlert` kembali mengizinkan alert.

### D. Alert Channels Unit Tests (`tests/Unit/AlertChannelsTest.php`)
- `test_database_channel_persists_alert`: Memverifikasi penyimpanan model `SecurityAlert` ke database SQLite.
- `test_telegram_channel_skips_when_unconfigured`: Memverifikasi graceful skip jika bot token atau chat ID kosong.
- `test_telegram_channel_dispatches_http_successfully`: Memverifikasi payload Telegram Markdown dan status HTTP 200 via `Http::fake()`.
- `test_telegram_channel_handles_api_failure_gracefully`: Memverifikasi bahwa jika Telegram API mengembalikan HTTP 500, channel mencatat log dan tidak melempar fatal exception ke aplikasi.
- `test_discord_channel_dispatches_http_successfully`: Memverifikasi payload embed Discord berwarna.
- `test_discord_channel_handles_failure_gracefully`: Memverifikasi penanganan graceful saat Discord rate limited (HTTP 429).
- `test_webhook_channel_sends_signature_header`: Memverifikasi pengiriman tanda tangan HMAC SHA-256 pada header `X-Security-Defense-Signature`.

### E. Preventive Middleware Feature Tests (`tests/Feature/RequestThreatScannerMiddlewareTest.php`)
- `test_clean_request_passes_through`: Request normal mendapatkan HTTP 200 tanpa interupsi.
- `test_it_blocks_sqli_query_payload`: Query string bermuatan SQLi otomatis diblokir dengan HTTP 403 dan alert tersimpan di database.
- `test_it_blocks_xss_in_json_body_with_json_response`: POST body dengan payload XSS diblokir dengan respons JSON 403 terstruktur (`error`, `message`, `threat_id`).
- `test_it_allows_excluded_paths_to_bypass_scanner`: Path yang terdaftar dalam `excluded_paths` tidak diblokir.

### F. End-to-End System Integration Test (`tests/Feature/SecurityDefenseEndToEndTest.php`)
- `test_full_detection_and_alerting_workflow`:
  - Telemetry disuplai via `SecurityDefense::record(...)`.
  - Domain event `ThreatDetected` dan `SecurityAlertCreated` terpancar.
  - Sanitasi kredensial terbukti aktif di database (password tidak tersimpan).
  - Metode `SecurityDefense::resolveAlert()` memperbarui status alert menjadi `resolved` dengan `resolved_at` dan memancarkan `SecurityAlertResolved`.
