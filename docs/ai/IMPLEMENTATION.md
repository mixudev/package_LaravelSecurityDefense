# Implementation Details — `mixudev/security-defense`

Dokumen ini mencatat rincian teknis komponen package pada HEAD. Bagian epistemic eksperimental, default off.

---

## 1. Directory Structure

```text
src/
├── Channels/          # Implementasi alert channel (Database, Telegram, Discord, Webhook, Mail)
├── Console/Commands/  # Artisan commands (auth:sync, prune, telegram poll/webhook, test-webhook)
├── Contracts/         # Interface dan abstraksi inti
├── DTO/               # Data Transfer Objects immutable (SecurityEvent, SecurityThreat)
├── Detection/         # Anomaly detection engine (AnomalyDetector)
├── Epistemic/         # Subsystem analisis epistemik (lihat bagian 7)
├── Events/            # Laravel Domain Events (ThreatDetected, SecurityAlertCreated, ...)
├── Exceptions/        # Package-specific exceptions
├── Http/              # Controllers (DashboardController, TelegramWebhookController) + middleware local access
├── Jobs/              # DispatchAlertChannelJob, ProcessSecurityDataAuditJob
├── Mail/              # SecurityAlertMail
├── Middleware/        # HTTP Middlewares (RequestThreatScanner, AuthenticatedSessionScanner, CSPArmor)
├── Models/            # Eloquent models (SecurityAlert, SecurityDataAudit, SecurityQuarantine)
├── Providers/         # Laravel Service Provider
├── Rules/             # 11 concrete detection rules
├── Services/          # Alert dedup, dispatcher, quarantine, scoring, telemetry, dashboard, audit, config writer, dll.
├── Sources/           # ThreatSource adapters (GenericArraySource, RequestThreatSource)
└── Support/           # Sanitizer, Facade, formatters, DateRangeFilter, traits

# src/Contracts/ berisi 5 interface inti; src/Epistemic/Contracts/ berisi 6 interface epistemic.
```

Catatan: direktori `src/Contracts/` berisi 5 interface inti. Interface epistemic terpisah di `src/Epistemic/Contracts/`. Subfolder `src/Epistemic/` berisi `AI/`, `Belief/`, `Correlation/`, `DTO/`, `Engine/`, `Evidence/`, `Feedback/`, `Graph/`, `Memory/`, `Policy/`, `Response/`, `ValueObjects/`, dan `EpistemicAnalyzer`.

---

## 2. Contracts & DTOs

### Contracts (`src/Contracts/`)

1. `Mixudev\SecurityDefense\Contracts\ThreatSource` — `toSecurityEvent(): SecurityEvent`.
2. `Mixudev\SecurityDefense\Contracts\DetectionRule` — `identifier()`, `name()`, `evaluate(SecurityEvent): ?SecurityThreat`, `isEnabled()`.
3. `Mixudev\SecurityDefense\Contracts\ThreatDetector` — `analyze(SecurityEvent): array`, `registerRule(DetectionRule): self`, `getRules(): array`.
4. `Mixudev\SecurityDefense\Contracts\AlertChannel` — `identifier()`, `send(SecurityAlert): bool`, `isConfigured()`, `isEnabled()`.
5. `Mixudev\SecurityDefense\Contracts\AlertDeduplicatorInterface` — `shouldAlert(SecurityThreat)`, `record(SecurityThreat)`, `forget(fingerprint)`.

### DTOs (`src/DTO/`)

`SecurityEvent`: immutable, normalisasi telemetry; properti `ip`, `identifier`, `eventType`, `timestamp`, `userAgent`, `metadata`; sanitasi via `Sanitizer` di constructor dan `fromArray()`. `SecurityThreat`: properti `severity`, `threatType`, `fingerprint`, `metadata`, `ruleIdentifier`, `detectedAt`; fingerprint SHA-256 deterministik (`threatType:target:signature`) bila tidak disuplai.

### Sanitizer (`src/Support/Sanitizer.php`)

- Scrubbing/masking `[REDACTED]` pada key `password`, `token`, `secret`, `authorization`, `bearer`, `cookie`, `cvv`, `credit_card`, `pin`, `otp`, `bot_token`, `webhook_url`, `two_factor_secret`, dan lainnya.
- Rekursif pada array berjenjang, batas kedalaman `hardening.max_traversal_depth` (5).
- Mendeteksi substring sensitif seperti `Bearer <token>` dan basic auth URL.

---

## 3. Detection Engine & Rules

### `AnomalyDetector` (`src/Detection/AnomalyDetector.php`)

- Mengimplementasi `ThreatDetector`, mengiterasi seluruh rule aktif, memancarkan event `ThreatDetected`.

### 11 Detection Rules (`src/Rules/`)

1. `BruteForceRule` — frekuensi kegagalan auth (`LoginFailed`, `OTP_FAILED`) per identifier; sliding window cache, threshold 10, severity high.
2. `CredentialStuffingRule` — banyak username berbeda dari satu IP; threshold 8 distinct identifiers, severity critical; sample identifier disimpan hash SHA-256.
3. `DistributedSprayRule` — satu identifier diserang banyak IP; threshold 5, severity high; sample IP disimpan hash SHA-256.
4. `RateLimitBypassRule` — rotasi header/identifier; threshold 15, severity medium.
5. `PayloadInjectionRule` — signature SQLi, XSS, traversal, command injection, eval, PHP code execution, template injection, CRLF, SSRF (localhost off default), XXE; method `inspect()` untuk scanning cepat; membersihkan control characters dari sample.
6. `ImpossibleTravelRule` — kecepatan Haversine antar login sukses; `max_speed_kmh=900`, window 3600, severity high; pakai cache lock.
7. `PathReconnaissanceRule` — probing file/dir sensitif (`.env`, `.git`, `wp-login`, dll.); threshold 3, window 120, severity high.
8. `UserAgentAnomalyRule` — scanner tools, empty UA, headless clients (semua configurable).
9. `SessionFingerprintRule` — fingerprint session vs header/IP; `session_ttl=7200`, severity high.
10. `BehavioralVelocityRule` — request per menit per user; threshold 120, severity high.
11. `HttpHeaderConsistencyRule` — inkonsistensi header antar request; severity medium.

---

## 4. Alert Persistence, Channels & Deduplication

- `SecurityAlert` (`src/Models/`) — tabel `security_alerts`; field `severity`, `threat_type`, `fingerprint`, `status` (`new`, `acknowledged`, `resolved`), `rule_identifier`, `metadata` JSON, `resolved_at`; mutator sanitasi via `Sanitizer::clean()`; scope `new()`, `acknowledged()`, `resolved()`, `severity()`.
- `AlertDeduplicator` (`src/Services/`) — cache key SHA-256 fingerprint, TTL `deduplication.window` (300).
- Channels (`src/Channels/`): `DatabaseChannel` (wajib), `TelegramChannel` (sendMessage, fail-safe), `DiscordChannel` (embed severity, fail-safe), `WebhookChannel` (HMAC SHA-256 header `X-Security-Defense-Signature`), `MailChannel` (email native Laravel via `SecurityAlertMail`).
- `AlertDispatcher` (`src/Services/`) — orkestrasi dedupe → fingerprint → save → broadcast channels → event `SecurityAlertCreated`; rate limiter `hardening.alert_rate_limit` (max 60/menit); potong metadata `max_alert_metadata_size` (16384).
- Channel queue via `DispatchAlertChannelJob`, diaktifkan `alerts.queue.enabled`.

---

## 5. Active Prevention Middleware

- `RequestThreatScanner` (`src/Middleware/`) — pre-controller; fast-path GET/HEAD tanpa query/body kecuali `scan_empty_requests=true`; TRACE/TRACK block; request flood limiter (default 200 req/s, jail 2 jendela, 429); payload scan; auto-jail critical; quarantine lookup cache + DB fallback (`security_quarantines`); pemrosesan telemetry ke detection engine; 403 JSON/HTML.
- `AuthenticatedSessionScanner` — session intelligence post-login (hijack, velocity, header anomaly).
- `ContentSecurityPolicyArmor` — inject CSP header nonce default bila `policy=null`.
- `EnsureLocalAccess` (`src/Http/Middleware/`) — batasi akses dashboard ke `dashboard.allowed_ips`/local-only.

---

## 6. Service Provider & Facade

- `SecurityDefenseServiceProvider` — bindings singleton, publish config/migrations, auto-load migrations, registrasi command, route dashboard, override config file.
- Facade `SecurityDefense` — `record()`, `processEvent()`, `resolveAlert()`, `detector()`, `dispatcher()`, `scoring()`, `quarantine()`, `analyze()`, `recordFeedback()`, `epistemic()`.

---

## 7. Epistemic Subsystem (`src/Epistemic/`)

- `EpistemicAnalyzer` — orkestrator pipeline; batas `limits.max_events=500`, `limits.max_evidence=500`, `ai.max_evidence=20`, metadata `4096`; graph bounded; AI evidence hanya saat ada trusted evidence; policy `decide()` ditegakkan hanya dengan response opt-in + adapter; dedup response execution via cache key.
- `Engine/EpistemicEngine` — confidence dari supporting/contradicting evidence.
- `Engine/RiskEngine` — risk dari belief + batas iterasi.
- `Belief/ThreatBelief`, `ThreatHypothesis` — hipotesis hasil korelasi.
- `Correlation/ThreatCorrelator`, `TemporalWindow` — korelasi dalam `windowSeconds`.
- `Graph/ThreatGraph`, `GraphNode`, `GraphEdge` — traversal bounded `max_depth=8`, `max_nodes=500`.
- `Evidence/` — `Evidence`, `EvidenceBuilder`, `EvidenceCollection`; sanitasi + batas metadata.
- `Policy/` — `PolicyEngine` (threshold 0.85/0.70/0.50/0.30), `ThreatDecision`, `DecisionAction`.
- `Memory/` — `ExperienceMemory` (cache, `max_patterns=10000`, `retention_days=30`, cache lock, fallback counter atomik, replay guard `feedbackId`), `ThreatPattern`.
- `Feedback/FeedbackHandler` — outcome hanya `confirmed_attack`/`false_positive`.
- `Response/` — `NoopResponseAdapter` (tanpa enforcement), `ResponseResult`.
- `AI/NullAiProvider` + `Contracts/AiEvidenceProviderInterface` — evidence source advisory, bukan decision authority.
- `ValueObjects/` — `Confidence`, `RiskScore`, `EvidenceType`.
- `DTO/AnalysisContext`, `DTO/ThreatAssessment` — batas event/evidence diterapkan analyzer, bukan DTO.

---

## 8. Data Audit, Dashboard & Lainnya

- `Services/DataAuditService`, `AuditPayloadSanitizer`, `DataAuditQueryService` + `Models/SecurityDataAudit` — mutasi DB, tamper detection, masked fields, honeypot `_system_sync_token`; queue `ProcessSecurityDataAuditJob`.
- `Services/DashboardAnalyticsService`, `SessionIntelligenceQueryService`, `ConfigWriterService` — data dashboard, overrides file, dot-key expansion.
- `Http/Controllers/DashboardController` + routes — multi-tab dashboard, IP quarantine management, quick-action toggles, live WAF events, date range filter, authorisasi Gate `security-defense.dashboard`.
- `Console/Commands/AuthSyncCommand` — generate bridge subscriber untuk `mixudev/laravel-authentication` + injeksi middleware WAF.
- `Support/DateRangeFilter`, `Support/Traits/HasSecurityAudit`, `Support/Facades/SecurityDefense`, `Support/ThreatResponseBuilder`, `Support/TelegramAlertFormatter`, `Support/DiscordAlertFormatter`.
- `Services/TelegramBotService`, `TelegramMessageComposer`, `TelegramApiClient` + `Console/Commands/TelegramPollCommand`, `TelegramWebhookCommand` — bot interaktif.