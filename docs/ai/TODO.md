# TODO Roadmap — `mixudev/security-defense`

Dokumen ini memantau status pengerjaan seluruh fase paket `mixudev/security-defense`.

---

## [Fase 1] Architecture, Setup & Core Contracts
- [x] Inisialisasi `composer.json`
- [x] Setup struktur direktori PSR-4 lengkap
- [x] Setup living documentation `docs/ai/*`
- [x] Implementasi Core Contracts (`ThreatSource`, `DetectionRule`, `ThreatDetector`, `AlertChannel`, `AlertDeduplicatorInterface`)
- [x] Implementasi DTOs (`SecurityEvent`, `SecurityThreat`)
- [x] Implementasi `Sanitizer` & `SecurityDefenseException`
- [x] Implementasi Adapters (`GenericArraySource`, `RequestThreatSource`)

## [Fase 2] Configuration & Service Provider
- [x] File konfigurasi lengkap `config/security-defense.php`
- [x] `SecurityDefenseServiceProvider` dengan binding singleton di Laravel Container
- [x] Facade `SecurityDefense` untuk akses statis yang ergonomis

## [Fase 3] Detection Engine & Rules
- [x] Engine `AnomalyDetector` yang stateless dan decoupled
- [x] Concrete Rules:
  - [x] `BruteForceRule` (sliding-window cache)
  - [x] `CredentialStuffingRule` (distinct accounts per IP)
  - [x] `DistributedSprayRule` (distinct IPs per account)
  - [x] `RateLimitBypassRule` (proxy chain spoofing & rapid cycling)
  - [x] `PayloadInjectionRule` (SQLi, XSS, Path Traversal, OS Command Injection)
  - [x] `ImpossibleTravelRule` (Haversine formula velocity check)

## [Fase 4] Persistence, Deduplication & Alert Channels
- [x] Database Migration `create_security_alerts_table` & Eloquent model `SecurityAlert`
- [x] Deduplication Service: `AlertDeduplicator`
- [x] Channels: `DatabaseChannel`, `TelegramChannel`, `DiscordChannel`, `WebhookChannel`
- [x] Domain Events: `ThreatDetected`, `SecurityAlertCreated`, `SecurityAlertResolved`

## [Fase 5] Active Prevention Middleware
- [x] `RequestThreatScanner` Middleware (inspeksi sebelum controller)
- [x] Safe payload extraction & pattern matching
- [x] Respons HTTP 403 terstruktur dan pencatatan alert otomatis

## [Fase 6] Enterprise Defense & Hardening (v1.1.0)
- [x] Anti-ReDoS string truncation bounds (`hardening.max_inspection_length`)
- [x] Anti-Memory Exhaustion recursion limit (`hardening.max_traversal_depth`)
- [x] Anti-Disk Exhaustion alert rate limiter (`hardening.alert_rate_limit`)
- [x] Compound `ThreatScoringEngine` (multi-vector risk score correlation)
- [x] `PathReconnaissanceRule` (deteksi probe `.env`, `.git`, `wp-login`, dll)
- [x] `UserAgentAnomalyRule` (deteksi `sqlmap`, `nikto`, scanner bot tools)
- [x] Active `IpQuarantineService` (Fail2Ban-style auto-jail & instant HTTP 429 rejection)
- [x] Asynchronous Queued Alert Delivery (`DispatchAlertChannelJob`, `ShouldQueue`)
- [x] 34 Unit & Feature tests (100% passing, 142 assertions)
- [x] Living documentation `docs/ai/*` diperbarui penuh
