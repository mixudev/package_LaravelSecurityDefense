# Implementation Details — `mixudev/security-defense`

Dokumen ini mencatat rincian teknis dari seluruh komponen package `mixudev/security-defense`. Bagian epistemic bersifat eksperimental dan belum siap produksi.

---

## 1. Directory Structure

```text
src/
├── Channels/          # Alert channel implementations (Database, Telegram, Discord, Webhook)
├── Contracts/         # Interfaces and abstractions
├── DTO/               # Immutable Data Transfer Objects (SecurityEvent, SecurityThreat)
├── Detection/         # Anomaly detection engine and correlation logic
├── Events/            # Laravel Domain Events (ThreatDetected, SecurityAlertCreated, SecurityAlertResolved)
├── Exceptions/        # Package-specific exceptions
├── Middleware/        # HTTP Middlewares (RequestThreatScanner)
├── Models/            # Eloquent models (SecurityAlert)
├── Providers/         # Laravel Service Provider
├── Rules/             # Concrete detection rule implementations
├── Services/          # Alert deduplication, dispatching, and coordinator services
├── Sources/           # ThreatSource adapters (GenericArraySource, RequestThreatSource)
└── Support/           # Sanitizer, Facades, Pattern matchers, Helper utilities
```

---

## 2. Contracts & DTOs

### Contracts
1. `Mixudev\SecurityDefense\Contracts\ThreatSource`
   - `toSecurityEvent(): SecurityEvent`
2. `Mixudev\SecurityDefense\Contracts\DetectionRule`
   - `identifier(): string`, `name(): string`, `evaluate(SecurityEvent $event): ?SecurityThreat`, `isEnabled(): bool`
3. `Mixudev\SecurityDefense\Contracts\ThreatDetector`
   - `analyze(SecurityEvent $event): array`, `registerRule(DetectionRule $rule): self`, `getRules(): array`
4. `Mixudev\SecurityDefense\Contracts\AlertChannel`
   - `identifier(): string`, `send(SecurityAlert $alert): bool`, `isConfigured(): bool`, `isEnabled(): bool`
5. `Mixudev\SecurityDefense\Contracts\AlertDeduplicatorInterface`
   - `shouldAlert(SecurityThreat $threat): bool`, `record(SecurityThreat $threat): void`, `forget(string $fingerprint): void`

### DTOs
1. `Mixudev\SecurityDefense\DTO\SecurityEvent`
   - Data immutable yang menormalisasi telemetry dari auth/request.
   - Properti: `ip`, `identifier`, `eventType`, `timestamp`, `userAgent`, `metadata`.
   - Menggunakan `Sanitizer::clean()` secara otomatis pada constructor dan `fromArray()`.
2. `Mixudev\SecurityDefense\DTO\SecurityThreat`
   - Hasil identifikasi ancaman dari rule.
   - Properti: `severity`, `threatType`, `fingerprint`, `metadata`, `ruleIdentifier`, `detectedAt`.
   - Fingerprint SHA-256 dibuat deterministik (`threatType:target:signature`) jika tidak disuplai manual.

### Sanitizer Support
`Mixudev\SecurityDefense\Support\Sanitizer`:
- Melakukan scrubbing dan masking `[REDACTED]` pada key: `password`, `token`, `secret`, `authorization`, `bearer`, `cookie`, `cvv`, `credit_card`, `pin`, `otp`, `bot_token`, `webhook_url`.
- Bekerja secara rekursif pada struktur array berjenjang.
- Mendeteksi dan mereplace substring sensitif seperti `Bearer <token>` dan basic auth URL.

---

## 3. Detection Engine & Rules

### `AnomalyDetector` (`src/Detection/AnomalyDetector.php`)
- Mengimplementasikan contract `ThreatDetector`.
- Mengiterasi seluruh rule aktif dan mengevaluasi `SecurityEvent`.
- Memancarkan event `ThreatDetected` langsung saat anomali ditemukan.

### 6 Concrete Detection Rules (`src/Rules/`)
1. **`BruteForceRule`**:
   - Memantau frekuensi kegagalan autentikasi (`LoginFailed`, `OTP_FAILED`) untuk satu akun/identifier.
   - Sliding window disimpan dalam cache dengan TTL otomatis.
   - Menghasilkan alert `brute_force` saat batas threshold tercapai.
2. **`CredentialStuffingRule`**:
   - Mendeteksi bot/attacker yang mencoba berbagai username berbeda dari 1 alamat IP dalam kurun waktu singkat.
   - Menghitung jumlah `distinct_identifiers` per IP.
3. **`DistributedSprayRule`**:
   - Mendeteksi serangan password spray terdistribusi di mana satu akun target diserang secara simultan oleh banyak IP berbeda.
   - Menghitung jumlah `distinct_ips` per identifier.
4. **`RateLimitBypassRule`**:
   - Mendeteksi indikasi pemalsuan header proxy (misalnya rantai `X-Forwarded-For` yang abnormal) atau rotasi IP cepat per user-agent/subnet.
5. **`PayloadInjectionRule`**:
   - Memeriksa string/array input terhadap signature serangan web utama:
     - SQL Injection (`UNION SELECT`, `' OR 1=1`, `information_schema`, `sleep()`, dll)
     - Cross-Site Scripting / XSS (`<script>`, `javascript:`, `onerror=`, `document.cookie`)
     - Path Traversal (`../`, `..\`, `/etc/passwd`, `win.ini`)
     - Command Injection (`; cat`, `| whoami`, `& dir`, `$(id)`)
   - Menyediakan method `inspect()` untuk scanning cepat oleh middleware WAF.
6. **`ImpossibleTravelRule`**:
   - Memantau anomali jarak geografis dan waktu antara dua aktivitas login sukses (`LoginSucceeded`, `NewDeviceLoginDetected`).
   - Menghitung kecepatan perpindahan menggunakan rumus Haversine. Jika kecepatan > `max_speed_kmh` (default 900 km/jam), ancaman ditandai.

---

## 4. Alert Persistence, Channels & Deduplication

### Persistence (`src/Models/SecurityAlert.php`)
- Model Eloquent yang menyimpan alert ke tabel `security_alerts`.
- Field: `severity`, `threat_type`, `fingerprint`, `status` (`new`, `acknowledged`, `resolved`), `rule_identifier`, `metadata` (JSON), `resolved_at`, `timestamps`.
- Mutator metadata secara otomatis memanggil `Sanitizer::clean()`.
- Scope query: `new()`, `acknowledged()`, `resolved()`, `severity($level)`.

### Deduplikasi (`src/Services/AlertDeduplicator.php`)
- Mencegah spam ribuan alert dari serangan berulang.
- Menggunakan cache key berbasis SHA-256 fingerprint dengan TTL `deduplication.window` (default 300 detik).

### Alert Channels (`src/Channels/`)
1. **`DatabaseChannel`**: Channel wajib utama untuk menyimpan alert ke database.
2. **`TelegramChannel`**: Mengirim ringkasan notifikasi Markdown via Telegram Bot API (`sendMessage`). Fail-safe: jika unconfigured atau API down, tidak memblokir aplikasi.
3. **`DiscordChannel`**: Mengirim embed Discord berwarna sesuai severity. Fail-safe dengan graceful logging.
4. **`WebhookChannel`**: Mengirim payload JSON ke endpoint eksternal/SIEM dengan header verifikasi tanda tangan HMAC SHA-256 (`X-Security-Defense-Signature`).

### `AlertDispatcher` (`src/Services/AlertDispatcher.php`)
- Mengorkestrasi alur: `Deduplication Check` -> `Record Fingerprint` -> `Database Save` -> `Broadcast Channels` -> `Dispatch SecurityAlertCreated Event`.

---

## 5. Active Prevention Middleware

### `RequestThreatScanner` (`src/Middleware/RequestThreatScanner.php`)
- Bekerja sebelum request mencapai controller aplikasi.
- Memeriksa URI path, query parameters, dan request body terhadap `PayloadInjectionRule`.
- Jika terdeteksi ancaman:
  1. Mencatat safe log (sanitized) via `Log::warning()`.
  2. Menerbitkan alert ke database dan channels via `AlertDispatcher`.
  3. Memblokir request dengan HTTP response 403 Forbidden (JSON untuk permintaan API, HTML ramah untuk permintaan browser).
- Mendukung pengecualian route via `config('security-defense.middleware.payload_scanner.excluded_paths')`.

---

## 6. Service Provider & Facade

- **`SecurityDefenseServiceProvider`**: Mengatur dependency injection singleton di Laravel Container, mempublikasikan konfigurasi dan migrasi, serta memuat migrasi secara otomatis.
- **`SecurityDefense` Facade**: Menyediakan interface statis yang bersih untuk `record()`, `processEvent()`, `resolveAlert()`, `detector()`, dan `dispatcher()`.
