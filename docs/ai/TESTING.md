# Testing Strategy & Validation — `mixudev/security-defense`

Dokumen ini mencatat rencana pengujian, jenis test yang dijalankan, dan validasi seluruh scenario package pada level Enterprise.

---

## 1. Lingkungan & Eksekusi Pengujian

- **Test Framework**: PHPUnit `11.5.56`
- **Laravel Testbench**: `orchestra/testbench` `10.11.0` (Laravel 12 Support)
- **Database Driver**: SQLite in-memory (`:memory:`)
- **Cache Driver**: Array Cache Store

Menjalankan pengujian:

```bash
vendor/bin/phpunit
# atau
composer test
```

---

## 2. Rincian Test Cases yang Dijalankan

Total: **34 tests, 142 assertions, 0 errors, 0 failures, 100% passing.**

### A. Sanitizer & DTO Unit Tests
- `tests/Unit/SanitizerTest.php`:
  - `test_it_redacts_sensitive_keys_recursively`: Masking `[REDACTED]` pada keys sensitif pada level root maupun nested array.
  - `test_it_scrubs_bearer_tokens_inside_strings`: Pembersihan substring Bearer token dari headers/payload.
- `tests/Unit/SecurityEventTest.php`:
  - `test_it_instantiates_and_sanitizes_metadata`: Verifikasi immutable DTO dan proteksi instan.
  - `test_from_array_factory`: Verifikasi factory method dari raw associative array.
- `tests/Unit/SecurityThreatTest.php`:
  - `test_it_creates_threat_with_sanitized_metadata_and_deterministic_fingerprint`: Verifikasi SHA-256 fingerprint deterministik.
  - `test_it_normalizes_invalid_severity_to_medium`: Normalisasi fallback severity.

### B. Core Detection Rules Unit Tests (`tests/Unit/DetectionRulesTest.php`)
- `test_brute_force_rule_detects_repeated_failed_attempts`: Uji batas threshold dan time window brute force.
- `test_credential_stuffing_rule_detects_multiple_accounts_from_one_ip`: Uji probe banyak akun dari 1 IP.
- `test_distributed_spray_rule_detects_multiple_ips_targeting_single_account`: Uji distributed password spray.
- `test_rate_limit_bypass_rule_detects_proxy_spoofing`: Uji anomali rantai header `X-Forwarded-For`.
- `test_payload_injection_rule_detects_sqli_and_xss`: Uji deteksi SQLi (`UNION SELECT`, `' OR 1=1`) dan XSS script tags dengan proteksi anti-ReDoS.
- `test_impossible_travel_rule_detects_excessive_speed`: Uji kecepatan Jakarta -> London dalam selang 1 detik (> 900 km/jam).

### C. Enterprise Detection Rules Unit Tests (`tests/Unit/EnterpriseRulesTest.php`)
- `test_path_reconnaissance_rule_detects_probing_sensitive_files`: Verifikasi deteksi probing `.env` dan `.git/config` saat mencapai threshold.
- `test_user_agent_anomaly_rule_detects_known_scanners`: Verifikasi identifikasi automated tools (`sqlmap`, `nikto`, `dirbuster`, `gobuster`, `wpscan`).
- `test_user_agent_anomaly_rule_ignores_legitimate_browsers`: Memastikan browser asli (Chrome, Safari) tidak teridentifikasi salah (*zero false positive*).

### D. Threat Scoring Engine Unit Tests (`tests/Unit/ThreatScoringEngineTest.php`)
- `test_it_aggregates_threat_scores_and_triggers_compound_threat`:
  - Rate limit bypass (+30 pts) -> Skor: 30
  - Brute force (+40 pts) -> Skor: 70
  - Payload injection (+50 pts) -> Total: 120 (>= 100). Otomatis menerbitkan `compound_threat` tingkat CRITICAL dengan daftar ancaman yang terlibat.

### E. IP Quarantine Service Unit Tests (`tests/Unit/IpQuarantineServiceTest.php`)
- `test_it_jails_and_pardons_an_ip`: Verifikasi fungsi `jail()`, pengecekan `isQuarantined()`, pengambilan metadata alasan, dan pembebasan `pardon()`.
- `test_whitelisted_ip_cannot_be_jailed`: Memastikan IP whitelist (`127.0.0.1`, `10.0.0.5`) tidak dapat dikarantina.

### F. Alert Channels & Deduplication Unit Tests (`tests/Unit/AlertChannelsTest.php` & `AlertDeduplicatorTest.php`)
- Deduplikasi fingerprint mencegah badai alert berulang dalam time window.
- `DatabaseChannel`: Persistensi model `SecurityAlert`.
- `TelegramChannel` & `DiscordChannel`: Uji pengiriman sukses dan fail-safe error handling saat API eksternal gagal.
- `WebhookChannel`: Uji pengiriman tanda tangan HMAC SHA-256 (`X-Security-Defense-Signature`).

### G. Asynchronous Queue Feature Test (`tests/Feature/QueuedAlertDispatchTest.php`)
- `test_it_pushes_alert_notifications_to_queue_when_queue_enabled`: Memvalidasi bahwa saat antrean aktif, pengiriman notifikasi dilempar ke `DispatchAlertChannelJob` (`ShouldQueue`) tanpa membebani response HTTP request.

### H. Preventive Middleware Feature Tests (`tests/Feature/RequestThreatScannerMiddlewareTest.php`)
- `test_clean_request_passes_through`: Request normal lolos HTTP 200.
- `test_it_blocks_sqli_query_payload_and_auto_jails`: Request SQLi diblokir HTTP 403, alert tersimpan di DB, dan IP otomatis masuk karantina. Request berikutnya dari IP tersebut langsung ditolak instan dengan HTTP 429 tanpa mengeksekusi regex.
- `test_it_blocks_xss_in_json_body_with_json_response`: Blokir XSS dengan respon JSON 403 terstruktur.
- `test_it_blocks_path_reconnaissance_probe`: Blokir probe ke `/.env` (HTTP 403).
- `test_it_blocks_automated_scanner_user_agent`: Blokir tool `sqlmap` (HTTP 403).
- `test_it_allows_excluded_paths_to_bypass_scanner`: Path dalam `excluded_paths` tetap lolos.

### I. End-to-End Integration Test (`tests/Feature/SecurityDefenseEndToEndTest.php`)
- Verifikasi alur lengkap: input telemetry -> anomaly evaluation -> threat scoring -> alert persistence -> sanitasi database -> resolusi alert via `SecurityDefense::resolveAlert()`.
