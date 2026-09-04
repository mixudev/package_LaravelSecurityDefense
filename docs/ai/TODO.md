# TODO Roadmap — `mixudev/security-defense`

Dokumen ini memantau status pengerjaan seluruh fase paket `mixudev/security-defense`.

---

## [Fase 1] Architecture, Setup & Core Contracts
- [x] Inisialisasi `composer.json` (`mixudev/security-defense`, PHP `^8.2`, Illuminate `^10|^11|^12`, Testbench `^8|^9|^10`)
- [x] Setup struktur direktori PSR-4 lengkap
- [x] Setup living documentation `docs/ai/*`
- [x] Implementasi Contracts:
  - [x] `ThreatSource`
  - [x] `DetectionRule`
  - [x] `ThreatDetector`
  - [x] `AlertChannel`
  - [x] `AlertDeduplicatorInterface`
- [x] Implementasi DTOs:
  - [x] `SecurityEvent`
  - [x] `SecurityThreat`
- [x] Implementasi Sanitizer & Exceptions:
  - [x] `Sanitizer`
  - [x] `SecurityDefenseException`
- [x] Implementasi Adapters:
  - [x] `GenericArraySource`
  - [x] `RequestThreatSource`

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
- [x] Database Migration: `create_security_alerts_table`
- [x] Eloquent Model: `SecurityAlert` dengan mutator sanitasi dan query scopes
- [x] Deduplication Service: `AlertDeduplicator` (fingerprint hash + time window)
- [x] Alert Dispatcher: `AlertDispatcher`
- [x] Channels:
  - [x] `DatabaseChannel` (Mandatory default)
  - [x] `TelegramChannel` (Optional, fail-safe)
  - [x] `DiscordChannel` (Optional, fail-safe)
  - [x] `WebhookChannel` (Optional SIEM/panel dengan tanda tangan HMAC SHA-256)
- [x] Domain Events:
  - [x] `ThreatDetected`
  - [x] `SecurityAlertCreated`
  - [x] `SecurityAlertResolved`

## [Fase 5] Active Prevention Middleware
- [x] `RequestThreatScanner` Middleware (inspeksi sebelum controller)
- [x] Safe payload extraction & pattern matching
- [x] Respons HTTP 403 terstruktur (JSON/HTML) dan pencatatan alert otomatis
- [x] Dukungan `excluded_paths`

## [Fase 6] Testing & Documentation Review
- [x] Setup PHPUnit 11 dan Orchestra Testbench
- [x] 25 Unit & Feature tests (100% passing, 90 assertions)
- [x] Validasi arsitektur final, decoupled auth, zero data leakage
- [x] Living documentation `docs/ai/*` diperbarui penuh
