# Changelog

Semua perubahan penting pada paket `mixudev/security-defense` didokumentasikan di file ini.

Format berbasis [Keep a Changelog](https://keepachangelog.com/id/1.1.0/), dan paket ini
mengikuti [Semantic Versioning](https://semver.org/lang/id/).

## [1.10.0] - 2026-09-29

### Ditambahkan

- **Lapisan otorisasi kedua pada dashboard (OTP)** — kode sekali pakai 8 karakter
  (`A-Z0-9`, ~41 bit entropy) dikirim keluar-band via email atau Telegram setelah IP
  whitelist lolos. Nonaktif secara default (`dashboard.otp.enabled`), sehingga alur
  satu-langkah existing tidak berubah.
  - `DashboardOtpService` — lifecycle kode: generate, hash-SHA256 di cache, consume-once,
    invalidasi setelah batas percobaan, burst limiter per IP.
  - `DashboardOtpDispatcher` — channel email / Telegram. Fail-closed: channel tidak
    terkonfigurasi = akses ditolak 403.
  - `DashboardOtpMail` + view `mail/otp.blade.php`.
  - Rute `GET|POST /security-defense/verify-code`.
  - Kode terikat ke `session_id + client IP`, sehingga tidak bisa dipakai ulang dari
    alamat lain maupun sesi lain.
- **Alert SIEM saat OTP brute-force** — ketika batas percobaan tercapai, package memancarkan
  `SecurityThreat` bertipe `dashboard_otp_brute_force` ke pipeline alert yang sudah ada
  (Telegram/Webhook/Log), sehingga percobaan break-in terhadap panel terlihat di monitoring.
- **`Support\CacheLock`** — helper penguncian cache terpusat dengan deteksi store yang benar
  (`$store instanceof LockProvider`) dan fallback graceful untuk driver yang tidak mendukung
  lock. Menyediakan `run()` untuk mutex dan `reserveSlot()` untuk kuota atomik.
- **`Support\ClientIpResolver`** — resolusi IP klien yang menghormati daftar
  `trusted_proxies`, dipakai bersama oleh `EnsureLocalAccess` dan `PortalController`.
- `SECURITY.md` — kebijakan pelaporan kerentanan.
- `LockGuardRegressionTest` — regression guard yang memindai seluruh `src/` untuk
  `method_exists($cache, 'lock')` yang selalu `false` terhadap wrapper `Repository`.

### Diperbaiki

- **Lock counters dan one-time token sekarang atomik.** Sebelumnya
  `method_exists($cache, 'lock')` selalu mengembalikan `false` terhadap
  `Illuminate\Cache\Repository` (lock diteruskan lewat magic `__call()`), sehingga setiap
  mutex di balik guard tersebut **tidak pernah benar-benar mengunci apa pun** saat runtime.
  Lokasi yang diperbaiki:
  - `DashboardOtpService` — consume-once dan failure counter
  - `AlertDispatcher` — slot rate-limit
  - `DashboardCapability::consume()` — token sekali pakai
  - `IpQuarantineService` — mutasi karantina/whitelist IP
  - `ImpossibleTravelRule` — riwayat lokasi
  - `ExperienceMemory` — memori pengalaman
- **Race condition pada counter OTP.** Register kegagalan dan burst limiter kini memakai
  pola atomik `add($key, 0, $ttl)` + `increment($key)` sebagai pengganti read-modify-write,
  sehingga request simultan tidak bisa melewati kuota per IP.
- **Halaman audit model** ikut mencatat penghapusan data (sebelumnya hanya create/update/read).
- **Kunci konfigurasi toggle user-agent** pada dashboard konsisten dengan nama key yang dibaca.
- **`AlertDispatcher`** tidak lagi menulis warning pada setiap request yang rate-limited.
- Dead code `advisoryAiEvidence` pada `EpistemicAnalyzer` dihapus.

### Keamanan

- Semua proteksi baru gagal-tertutup (fail-closed): tanpa channel OTP, dashboard menolak
  masuk (403), bukan meloloskan.
- Kode OTP tidak pernah masuk log, response body, atau header.
- Perbandingan kode memakai `hash_equals()` (constant-time).

### Catatan Upgrade

- Tidak ada perubahan breaking. Semua fitur baru default nonaktif atau backwards-compatible.
- Untuk mengaktifkan OTP, tambahkan ke `.env`:
  ```dotenv
  SECURITY_DEFENSE_OTP_ENABLED=true
  SECURITY_DEFENSE_OTP_CHANNEL=email
  SECURITY_DEFENSE_OTP_EMAIL=ops@example.com
  ```
  Untuk Telegram, set `SECURITY_DEFENSE_OTP_CHANNEL=telegram` dan pastikan
  `alerts.telegram.*` sudah terisi.
- Jika config di-publish manual, tambahkan blok `dashboard.otp` (lihat `docs/02-konfigurasi.md`).
  Alternatif: `php artisan vendor:publish --tag=security-defense-config --force`.
- **Disarankan** memakai cache driver Redis/Memcached di production. Driver `file`/`array`
  tidak menjamin lock antar-proses.
