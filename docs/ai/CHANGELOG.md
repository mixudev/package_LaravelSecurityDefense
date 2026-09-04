# Changelog — `mixudev/security-defense`

Seluruh pembaruan penting pada package dicatat di sini.

Format berbasis pada [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [1.1.0] - 2026-09-04

### Added
- **Self-Defense & Hardening (Zero Vulnerability Guarantee)**:
  - Pembatasan panjang string inspeksi (`hardening.max_inspection_length`) untuk mencegah serangan ReDoS (*catastrophic backtracking*).
  - Pembatasan kedalaman rekursi (`hardening.max_traversal_depth`) pada `Sanitizer` untuk mencegah memory/stack exhaustion.
  - Alert Rate Limiting (`hardening.alert_rate_limit`) untuk mencegah eksploitasi disk exhaustion pada database server.
  - Penanganan aman pada lingkungan standalone/CLI unbooted container di `Sanitizer`.
  - Dukungan kompatibilitas penuh untuk **Laravel 10, 11, 12, dan 13** (`illuminate/*: ^10.0|^11.0|^12.0|^13.0`, dual `$casts` + `casts(): array` method).
- **Compound Threat Scoring Engine**:
  - `ThreatScoringEngine` mengagregasi skor risiko dari berbagai vektor serangan per entitas dalam sliding window (default 15 menit).
  - Menghasilkan alert `compound_threat` (CRITICAL) otomatis saat skor melampaui batas threshold (100).
- **Enterprise Rules Baru**:
  - `PathReconnaissanceRule`: Mendeteksi probing bot terhadap file/direktori sensitif (`.env`, `.git`, `wp-login`, `actuator`, `phpinfo`, database dumps).
  - `UserAgentAnomalyRule`: Mendeteksi automated scanner tools (`sqlmap`, `nikto`, `dirbuster`, `gobuster`, `wpscan`, `masscan`, `nmap`).
- **Active IP Quarantine (Fail2Ban-Style Defense)**:
  - `IpQuarantineService` untuk isolasi sementara IP penyerang dengan TTL cache otomatis.
  - Integrasi ke `RequestThreatScanner`: penolakan instan (HTTP 429) di baris pertama middleware untuk menghemat CPU saat terjadi serangan masif.
  - Auto-jailing otomatis saat ancaman injeksi kritis terdeteksi.
  - Perlindungan daftar putih (`whitelist`) untuk localhost dan proxy internal.
- **Asynchronous Queue Dispatching**:
  - `DispatchAlertChannelJob` (`ShouldQueue`) untuk offloading pengiriman notifikasi Telegram/Discord/SIEM ke background worker (zero request latency).

---

## [1.0.0] - 2026-09-04

### Added
- Inisialisasi awal arsitektur modular security defense.
- Core contracts: `ThreatSource`, `DetectionRule`, `ThreatDetector`, `AlertChannel`, `AlertDeduplicatorInterface`.
- Core rules: `BruteForceRule`, `CredentialStuffingRule`, `DistributedSprayRule`, `RateLimitBypassRule`, `PayloadInjectionRule`, `ImpossibleTravelRule`.
- Channels: `DatabaseChannel`, `TelegramChannel`, `DiscordChannel`, `WebhookChannel`.
- Living documentation di `docs/ai/*`.
