# Changelog — `mixudev/security-defense`

Seluruh pembaruan penting pada package dicatat di sini.

Format berbasis pada [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [1.0.0] - 2026-09-04

### Added
- **Core Architecture & Contracts**:
  - `ThreatSource` contract untuk menerima security event dari sumber mana pun secara independen dari framework auth.
  - `DetectionRule` contract untuk rules anomali yang modular dan extensible.
  - `ThreatDetector` contract untuk engine evaluasi ancaman.
  - `AlertChannel` contract untuk modul pengiriman notifikasi.
  - `AlertDeduplicatorInterface` contract untuk penekanan alert duplikat berbasis fingerprint hash.
- **DTOs & Data Privacy**:
  - `SecurityEvent` DTO ternormalisasi dengan auto-sanitization.
  - `SecurityThreat` DTO dengan deterministic SHA-256 fingerprint generation.
  - Utilitas `Sanitizer` untuk pembersihan rekursif password, token, secret, dan authorization headers.
- **Adapters**:
  - `GenericArraySource`: Adapter untuk array associatif dari event auth Laravel / webhook eksternal.
  - `RequestThreatSource`: Adapter untuk objek `Illuminate\Http\Request`.
- **Detection Rules**:
  - `BruteForceRule`: Deteksi serangan brute force ke satu akun.
  - `CredentialStuffingRule`: Deteksi bot yang mencoba banyak akun dari 1 alamat IP.
  - `DistributedSprayRule`: Deteksi serangan password spray terdistribusi dari banyak IP ke 1 akun.
  - `RateLimitBypassRule`: Deteksi manipulasi header proxy atau rotasi IP cepat.
  - `PayloadInjectionRule`: Deteksi pola SQLi, XSS, Path Traversal, dan Command Injection.
  - `ImpossibleTravelRule`: Deteksi anomali kecepatan perpindahan geografis antar-login berbasis rumus Haversine.
- **Engine & Coordinator**:
  - `AnomalyDetector`: Detection engine yang mengorkestrasi evaluasi rule dan pemancaran event `ThreatDetected`.
  - `SecurityDefenseManager`: Master coordinator untuk telemetry recording, pipeline deteksi, dan resolusi alert.
  - Facade `SecurityDefense` untuk pemanggilan statis yang ergonomis.
- **Persistence & Alert Subsystem**:
  - Database migration `create_security_alerts_table` dan Eloquent model `SecurityAlert`.
  - `AlertDeduplicator`: Layanan deduplikasi berbasis cache sliding-window.
  - `AlertDispatcher`: Orkestrator pengiriman alert ke database dan channel pihak ketiga.
  - `DatabaseChannel`: Channel default wajib untuk persistence.
  - `TelegramChannel`: Notifikasi Telegram Markdown dengan fail-safe error handling.
  - `DiscordChannel`: Notifikasi Discord Embed dengan fail-safe error handling.
  - `WebhookChannel`: Integrasi eksternal/SIEM dengan tanda tangan HMAC SHA-256.
- **Active Prevention**:
  - `RequestThreatScanner` Middleware: WAF-level payload scanner yang memblokir serangan sebelum mencapai controller dengan respons HTTP 403 terstruktur.
- **Domain Events**:
  - `ThreatDetected`
  - `SecurityAlertCreated`
  - `SecurityAlertResolved`
- **Testing Suite**:
  - 25 unit dan feature test menyeluruh menggunakan PHPUnit dan Orchestra Testbench (100% lulus).
- **Living Documentation**:
  - Folder `docs/ai/` lengkap (`README.md`, `ARCHITECTURE.md`, `DECISIONS.md`, `IMPLEMENTATION.md`, `SECURITY.md`, `CONFIGURATION.md`, `INTEGRATION.md`, `TESTING.md`, `CHANGELOG.md`, `TODO.md`).
