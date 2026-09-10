# Changelog — `mixudev/security-defense`

Seluruh pembaruan penting pada package dicatat di sini.

Format berbasis pada [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

### Changed
- Dokumentasi epistemic diperbarui untuk API array `SecurityDefense::analyze`, outcome feedback `confirmed_attack`/`false_positive`, batas input dan graph, memory cache, replay guard, cache lock, provider AI advisory, response adapter default-off, API publik, migrasi, dan config cache.
- Status epistemic ditegaskan sebagai eksperimental dan belum siap produksi.

---

## [1.2.0] - 2026-09-04

### Enterprise Scale & Aggressive Bot Hunting

### Added
- **Per-IP Request Flood Limiter** (`middleware.request_flood`) — counter windowed
  O(1) atomic (`cache->increment()`) di `RequestThreatScanner` sebelum semua scan
  regex. IP yang melebihi cap ditolak 429 dan auto-quarantine (fail-closed saat
  serangan masif). Env: `SECURITY_DEFENSE_FLOOD_PROTECTION` (default true).
- **Fast-path payload scan** — regex `PayloadInjectionRule::inspect()` dilewati
  untuk request tanpa query dan tanpa body (GET/HEAD polos) kecuali
  `middleware.payload_scanner.scan_empty_requests=true`. Memotong biaya CPU
  hampir ke nol untuk trafik jutaan request.
- **HTTP Method Abuse block** — `TRACE`/`TRACK` diblokir tanpa syarat
  (vektor reflected-XSS, tidak ada kegunaan sah).
- **Bot hunting diperluas** — daftar scanner `UserAgentAnomalyRule` ditambah:
  ffuf, dirsearch, zmap, cadaver, wfuzz, testssl, whatweb, sublist3r, katana,
  jaeles, dalfox, xsstrike, commix, tplmap, arachni, wapiti.

### Changed
- **`ThreatScoringEngine` race-free** — skor agregat kini pakai counter atomik
  (`cache->increment()`), bukan read-modify-write yang racy di bawah concurrent
  threats. Cache records dibatasi (`detection.scoring.max_records`, default 50)
  agar memori cache tidak tumbuh tanpa batas.

### Tests
- `RequestThreatScannerEnterpriseTest` baru (5 test): fast-path, query tetap
  discan, TRACE block, flood limiter jail, scanner UA diperluas.
- Total suite: 77 tests, 300 assertions hijau.

---

## [1.1.4] - 2026-09-04

### Email Theme Fix — always light default (no class-detectable theme)

### Changed
- **Hapus tema dark dari template email** — blok `@media (prefers-color-scheme: dark)`
  di `emails/layouts/html.blade.php` dihapus. Sebelumnya, pembaca dengan mode
  OS/email client gelap melihat email dirender dark (#09090b/#18181b) karena
  media query. Sekarang template **selalu light profesional**, tanpa tema,
  terlepas dari mode reader.

### Fixed
- Email kini render konsisten light di semua client: card `#ffffff`, bg `#f4f4f5`,
  text `#09090b`/`#18181b` (dark text on light, bukan background dark).

### Tests
- `EmailRenderTest` diperkuat: memverifikasi TIDAK ada `prefers-color-scheme`,
  `@media`, dan tidak ada background dark — template selalu light.

---

## [1.1.3] - 2026-09-04

### Email & Messaging Template Refactor (maintainable templating)

### Changed
- **Email alert pakai layout + komponen modular** — `emails/alert.blade.php` kini
  `@extends('security-defense::emails.layouts.html')` dan memakai komponen
  `emails/components/*` (`badge`, `detail-row`, `telemetry`), konsisten dengan
  layout/header/footer yang sudah ada.
- **Email tema light profesional** — hapus background dark navy (`#0b0f19`/`#111827`);
  email kini light (#ffffff card) dengan adaptasi otomatis `prefers-color-scheme: dark`
  di layout untuk pembaca mode gelap.
- **Discord templating terpusat** — payload embed dipindah ke
  `Support\DiscordAlertFormatter` (title, fields, color, footer), `DiscordChannel`
  tinggal transport. Hapus emoji `🛡️`, tone profesional.
- **Telegram templating terpusat** — pesan markdown dipindah ke
  `Support\TelegramAlertFormatter`; label severity teks (`[CRITICAL]`) ganti emoji
  (`🚨⚠️⚡ℹ️`).
- Internal diagnostic keys (`_is_test`, `source`) dikeluarkan dari blok metadata
  publik pada pesan Discord/Telegram.

### Added
- Test `EmailRenderTest` — memverifikasi email memakai layout modular, tema light,
  badge severity, telemetry ter-sanitasi, footer.
- Test `MessageFormatterTest` — memverifikasi formatter Discord & Telegram:
  struktur profesional, tanpa emoji, warna severity benar, kunci internal disaring.

---

## [1.1.2] - 2026-09-04

### UI/UX & Accessibility Pass (dashboard views)

### Changed
- **Semua emoji diganti SVG ikon inline** (Lucide-style) — memenuhi preferensi tanpa-emoji. Berdampak: `channel-card` (ikon per-kanal), `quarantine-table` (shield-alert), `emails/alert` (header emoji dihapus).
- **Severity badge aksesibel** — `alerts-table` kini memakai dot indikator berwarna + teks, bukan hanya warna (ramah daltonisme).
- **Threat Distribution di-refactor jadi progress bar proporsional** — `threat-distribution` menampilkan bar + persentase, bukan sekadar chip.
- **Card label channel proper** — `channel-card` menampilkan `Webhook`/`Discord`/`Telegram`/`Email`/`Database` (sebelumnya raw key).
- **Timestamp lebih manusiawi** — `quarantine-table` memakai `diffForHumans()`.
- **Aksesibilitas tombol Release** — `aria-label` ditambahkan.
- **Hardening tamahan**: count telemetry di-escape (`count()` tetap int, tapi diganti dari `{!! !!}` ke `{{ }}`).

### Added
- Test baru `DashboardRenderDataTest` — renders dashboard dengan data terisi (alerts + quarantines + distribution) dan memverifikasi bebas emoji.

### Fixed
- **Toggle dark/light mode tidak mengubah gaya** — akar masalah: Tailwind v4 browser runtime default memakai `prefers-color-scheme` (media query OS), bukan class. Ditambahkan `<style type="text/tailwindcss">` dengan `@custom-variant dark (&:where(.dark, .dark *));` di `layouts/app.blade.php` sehingga class `.dark` pada `<html>` menggerakkan semua varian `dark:`. (Alpine tidak diperlukan — toggle murni vanilla JS.)

### Docs
- Folder `docs/` modular baru untuk integrasi & kustomisasi: `README.md`, `01-installation.md`, `02-integration.md`, `03-alert-channels.md`, `04-dashboard.md`, `05-customization.md`, `06-security-hardening.md`, `07-testing.md`, `08-troubleshooting.md`.

---

## [1.1.1] - 2026-09-04

### Security Hardening (audit-driven remediation)

Semua 13 temuan dari audit keamanan telah diperbaiki.

### Fixed (CRITICAL)
- **Race condition pada detection counters** — BruteForceRule, CredentialStuffingRule, DistributedSprayRule, PathReconnaissanceRule, RateLimitBypassRule kini menggunakan atomic `cache->increment()` (sebelumnya read-modify-write `get()`→`put()` yang bisa di-bypass oleh parallel request).
- **Race condition pada alert rate limiter** — `AlertDispatcher::incrementRateLimiter()` kini selalu `increment()` dengan TTL di-seed hanya saat penciptaan pertama (sebelumnya TOCTOU bisa membuat counter stuck di 1 → unlimited alerts).

### Fixed (HIGH)
- **Bypass IP quarantine via cache loss** — Tambahan `IpQuarantineService` mendukung persistence DB opsional (`SecurityQuarantine` model + tabel `security_quarantines`, diaktifkan via `SECURITY_QUARANTINE_PERSIST_DB=true`). Cache = fast path, DB = authoritative fallback.
- **Information leak: payload sample** — `PayloadInjectionRule` membersihkan control characters (`/[\x00-\x1f\x7f]/`) dari `matched_sample`/`matched_signature` (mencegah log/Markdown injection & persistent XSS).
- **Information leak: identifier & IP list** — `CredentialStuffingRule` menyimpan `sample_identifiers_hashed` (SHA-256) dan `DistributedSprayRule` menyimpan `sample_ips_hashed` (SHA-256), bukan plaintext.
- **TOCTOU ImpossibleTravelRule** — Akses baca-tulis lokasi kini dibungkus cache lock untuk mencegah race condition pada concurrent login.

### Fixed (MEDIUM)
- **Empty User-Agent bypass** — Konfigurasi baru `user_agent_anomaly.block_empty_user_agent` (env `SECURITY_DEFENSE_BLOCK_EMPTY_UA`) mengaktifkan deteksi klien tanpa User-Agent (default off untuk menjaga perilaku existing).
- **Header overexposure** — `RequestThreatSource` kini menyimpan hanya hash SHA-256 dari `x-forwarded-for`/`cf-connecting-ip`; `origin`/`referer` mentah tidak lagi tersimpan.
- **Queue job arbitrary class** — `DispatchAlertChannelJob` memvalidasi `channelClass` terhadap whitelist (`VALID_CHANNELS`) sebelum instansiasi.
- **Metadata unbounded** — `AlertDispatcher` memotong metadata saat JSON melebihi `hardening.max_alert_metadata_size` (default 16KB).
- **Middleware tidak feed detection engine** — `RequestThreatScanner::handleDetectedAnomaly()` kini juga memanggil `processEvent()` agar telemetry request mengalir ke seluruh detection rules.

### Added
- Model `SecurityQuarantine` + migration tabel `security_quarantines`.
- 12 test regresi keamanan baru (total 46 tests, 185 assertions).

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
