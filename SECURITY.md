# Security Policy

Keamanan adalah prioritas utama paket ini. Package ini memproses input HTTP yang tidak tepercaya, mengelola secret webhook, dan menyimpan metadata IP dalam cache. Kerentanan pada lapisan ini berdampak langsung pada host aplikasi.

## Versi yang Didukung

| Versi | Didukung |
|---|---|
| 1.9.x | Ya |
| < 1.9 | Tidak — upgrade dulu |

## Melaporkan Kerentanan

Jangan buka public issue untuk melaporkan kerentanan. Public issue membuat detail eksploitasi dapat diakses semua orang sebelum ada perbaikan.

Gunakan GitHub Private Vulnerability Reporting:

1. Buka https://github.com/mixudev/package_LaravelSecurityDefense/security/advisories/new
2. Pilih "Report a vulnerability"
3. Isi detail temuan

Jika metode tersebut tidak tersedia, kirim laporan awal (tanpa payload eksploitasi) lewat Telegram ke @mixudev, lalu tunggu instruksi kanal privat.

### Yang perlu disertakan

- Versi paket (`composer show mixudev/security-defense`)
- Versi PHP dan Laravel
- Konfigurasi relevan (`security-defense.enabled`, `dashboard.*`, `alerts.queue.*`) — hapus nilai secret dan IP internal sebelum mengirim
- Langkah reproduksi minimal, atau testbench yang gagal
- Dampak teramati: bypass WAF, kebocoran secret, atau tulis ke database tanpa otorisasi

### Yang diharapkan

| Tahap | Target |
|---|---|
| Konfirmasi | 3 hari kerja |
| Triage awal dan severity | 7 hari kerja |
| Patch rilis | 30 hari kerja sejak konfirmasi |

Kerentanan yang sudah dieksploitasi di Alam liar, atau yang menuntut bypass fail-closed, diprioritaskan di atas jadwal tersebut.

## Cakupan

Dalam cakupan:

- Bypass deteksi pada `RequestThreatScanner`, rules WAF, atau deteksi user-agent
- Kebocoran secret: webhook secret, opaque dashboard path, `DashboardCapability`
- Otorisasi dashboard: `EnsureLocalAccess`, `ValidateOpaqueDashboardPath`, `DashboardAccessPolicy`
- Integritas audit trail: `DataAuditService`, `HasSecurityAudit`, entity yang diaudit
- SQLi, XSS, path traversal, atau command injection di output dashboard
- CSRF pada quick-action toggle atau endpoint dashboard yang menulis state
- Kebocoran data sensitif lewat metadata alert, log, atau cache

Di luar cakupan:

- Aplikasi host yang mengabaikan rekomendasi setup package
- `dashboard.local_only = false` di jaringan publik (pilihan operator, bukan kerentanan)
- Denial-of-service di lapisan jaringan atau transport
- Lapisan framework di luar versi yang didukung di tabel atas

## Praktik Operasional

- Dashboard dibatasi `local_only = true` dan `allowed_ips` secara default. Jangan longgarkan tanpa WAF di depan.
- `SECURITY_DEFENSE_KEY` wajib diisi di produksi. Bila kosong, sistem memakai `app.key` sebagai fallback untuk opaque path. Rotasi `app.key` akan mengakhiri sesi dashboard yang sedang aktif (dokumentasi di `docs/03-dashboard.md`).
- Webhook channel fail-closed: secret kosong berarti request ditolak 401, bukan diterima.
- Package tidak menyimpan password, token, atau nomor kartu dalam log. Redaksi berada di `AuditPayloadSanitizer` dan sudah tercakup tes regresi.
