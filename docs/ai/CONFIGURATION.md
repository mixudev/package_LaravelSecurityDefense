# Configuration Reference — `mixudev/security-defense`

Sumber kebenaran konfigurasi: `config/security-defense.php`. Nilai di bawah adalah default file pada HEAD.

## Top-level

| Kunci | Default |
|---|---|
| `enabled` | `true` |
| `cache_store` | `null` |
| `cache_prefix` | `'security_defense:'` |

## `hardening`

`max_inspection_length=4096`, `max_traversal_depth=5`, `max_alert_metadata_size=16384`, `alert_rate_limit.enabled=true`, `alert_rate_limit.max_alerts_per_minute=60`.

## `detection`

- `enabled=true`.
- `scoring`: `enabled=true`, `threshold=100`, `window=900`, `max_records=50`.
- `scoring.weights`: `brute_force=35`, `credential_stuffing=45`, `distributed_spray=30`, `rate_limit_bypass=20`, `payload_injection=50`, `impossible_travel=35`, `path_reconnaissance=30`, `user_agent_anomaly=25`, `session_fingerprint=45`, `behavioral_velocity=35`, `header_consistency=25`.
- `rules.brute_force`: enabled, threshold `10`, window `60`, severity `high`, events `LoginFailed`, `OTP_FAILED`.
- `rules.credential_stuffing`: enabled, threshold `8`, window `120`, severity `critical`, event `LoginFailed`.
- `rules.distributed_spray`: enabled, threshold `5`, window `300`, severity `high`, event `LoginFailed`.
- `rules.rate_limit_bypass`: enabled, threshold `15`, window `60`, severity `medium`.
- `rules.payload_injection`: enabled, severity `critical`, patterns `sqli`, `xss`, `traversal`, `command_injection`, `eval_based`, `php_code_execution`, `template_injection`, `crlf_injection`, `ssrf`, `ssrf_localhost=false`, `xxe`.
- `rules.impossible_travel`: enabled, `max_speed_kmh=900`, window `3600`, severity `high`, events `LoginSucceeded`, `NewDeviceLoginDetected`.
- `rules.path_reconnaissance`: enabled, severity `high`, threshold `3`, window `120`.
- `rules.user_agent_anomaly`: enabled, severity `medium`, `block_known_scanners=true`, `block_empty_user_agent=false`, `block_headless_clients=false`.
- `rules.session_fingerprint`: enabled, severity `high`, `session_ttl=7200`.
- `rules.behavioral_velocity`: enabled, threshold `120`, window `60`, severity `high`.
- `rules.header_consistency`: enabled, severity `medium`.

## `alerts`

- `queue`: enabled `false`, connection `null`, queue name `security-alerts`.
- `database`: enabled `true`, table `security_alerts`.
- `telegram`: enabled `true`, token/chat ID from `SECURITY_TELEGRAM_BOT_TOKEN`/`SECURITY_TELEGRAM_CHAT_ID`, timeout `5`, interactive enabled.
- `discord`: enabled `true`, URL from `SECURITY_DISCORD_WEBHOOK`, timeout `5`.
- `webhook`: enabled `false`, URL/secret from `SECURITY_WEBHOOK_URL`/`SECURITY_WEBHOOK_SECRET`, timeout `5`.
- `mail`: enabled `false`, recipient `SECURITY_ALERT_EMAIL`, subject prefix `[SECURITY DEFENSE ALERT]`, timeout `10`.

## Other top-level groups

- `deduplication`: enabled `true`, window `300`.
- `middleware.payload_scanner`: enabled `true`, action `block`, status `403`, default message, `scan_empty_requests=false`, `excluded_paths=[]`.
- `middleware.request_flood`: enabled `true`, max `200` requests/second, window `5`, jail after `2` windows.
- `middleware.quarantine`: enabled `true`, duration `900`, auto-jail critical `true`, status `429`, default message, DB persistence `false`, `db_fail_closed=false`, table `security_quarantines`, whitelist `127.0.0.1`, `::1`.
- `dashboard`: enabled `true`, local-only `true`, localhost whitelist, cache enabled TTL `30`, rate limit enabled `30` probes/minute. (Config file defines `dashboard` twice; PHP's later definition wins, so `path` is not part of the effective config array.)
- `data_audit`: enabled `true`, table `security_data_audits`, tampering alerts enabled, model watch list, masked/excluded/sensitive field lists, honeypot `_system_sync_token`, snapshot limit `8192`, queue disabled (`security-audit`), retention `30`, tampered retention `90`.
- `csp_armor`: enabled `true`, report-only `false`, policy `null`.
- `session_intelligence`: enabled `true`, `block_on_hijack=false`.

## `epistemic`

| Kunci | Default |
|---|---:|
| `enabled` | `false` |
| `confidence.min`, `confidence.max` | `0.0`, `1.0` |
| `risk.epsilon`, `risk.max_iterations`, `risk.decay` | `0.001`, `10`, `0.95` |
| `graph.max_depth`, `graph.max_nodes`, `graph.window_seconds` | `8`, `500`, `900` |
| `limits.max_events`, `limits.max_evidence`, `limits.max_metadata_bytes` | `500`, `500`, `4096` |
| `ai.max_evidence`, `ai.max_metadata_bytes`, `ai.allowed_future_seconds` | `20`, `4096`, `60` |
| `memory.retention_days`, `memory.max_patterns` | `30`, `10000` |
| `policy.block_threshold`, `quarantine_threshold`, `challenge_threshold`, `monitor_threshold` | `0.85`, `0.70`, `0.50`, `0.30` |
| `response.enabled`, `response.adapter` | `false`, `null` |

`response.dedup_ttl` juga dibaca internal analyzer dengan fallback `300`, tetapi belum menjadi key default pada file konfigurasi. `epistemic.response.enabled=false` berarti tidak ada enforcement tanpa adapter yang dikonfigurasi dan opt-in.

Saat config cache aktif, jalankan `php artisan config:clear`, verifikasi, lalu `php artisan config:cache`.
