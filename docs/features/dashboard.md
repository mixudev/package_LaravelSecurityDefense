# Dashboard Monitoring & Quick Actions

Panel monitoring SIEM terintegrasi dengan pure dark theme, live telemetry, dan
kontrol pertahanan langsung dari antarmuka web.

## Fitur

| Fitur | Lokasi | Deskripsi |
|---|---|---|
| KPI Cards | Dashboard | Total threats, pending triage, critical/high, quarantined IPs |
| Quick Actions | Dashboard | Toggle live: Block Headless Clients, CSP Armor, Async Audit Queue |
| Date Range Filter | Semua halaman | Preset Today / 7 Days / 30 Days |
| Live WAF Events | Dashboard | 10 event block terbaru, auto-refresh 5 detik |
| IP Quarantine Mgmt | Dashboard | Release IP + Whitelist permanen per baris |
| Alerts Table | Dashboard | Correlated telemetry + filter status/severity |
| Database Audits | `/data-audits` | Mutation log, diff inspection modal, filter event/model/tampered |
| Session Intelligence | `/sessions` | Client-side threats, filter vector/severity |

## Quick Actions — Persistence

Toggle di dashboard menulis ke file `config/security-defense-overrides.php`
(mekanisme `ConfigWriterService`), yang di-merge di atas config utama saat boot.
Keuntungan:

- Config utama (`config/security-defense.php`) tetap pristine — tak disentuh.
- Override bertahan walau cache di-flush atau restart.
- Nested dot-notation key didukung (Laravel config merge).

Toggle yang tersedia (whitelist ketat — tak bisa menulis key arbitrer):

| Key | Config Path | Default |
|---|---|---|
| `block_headless_clients` | `middleware.user_agent_anomaly.block_headless_clients` | `false` |
| `csp_armor` | `csp_armor.enabled` | `true` |
| `async_queue` | `data_audit.queue.enabled` | `false` |

Jika `config_path()` tidak writable, toggle berlaku hanya session (runtime),
dengan pesan peringatan di UI.

## IP Quarantine Management

Tabel aktif di dashboard menampilkan setiap IP yang di-jail (Fail2Ban style):

- **Release IP** — `POST /security-defense/quarantine/pardon` → hapus quarantine
  (cache + DB jika persist_to_database aktif).
- **Whitelist IP** — `POST /security-defense/quarantine/whitelist` → tambah ke
  whitelist permanen via overrides file + langsung pardon. IP whitelisted tak
  pernah di-jail lagi.

Keduanya memakai `EnsureLocalAccess`: mode lokal mensyaratkan environment `local` + `allowed_ips`; mode publik (opt-in) mensyaratkan `public.enabled`, IP/CIDR allowlist, user terautentikasi, dan authorization Gate.

## Live WAF Events

Endpoint `GET /security-defense/live-events` mengembalikan JSON 10 alert
terbaru. Komponen `live-events-table` melakukan polling tiap 5 detik.
Data diambil dari `SecurityAlert` (severity badge, threat type, source IP,
method + URL, relative time).

## Date Range Filter

Komponen `date-range-filter` tersedia di dashboard, data-audits, dan sessions.
Preset: **Today**, **7 Days**, **30 Days** (default 30d). Filter preserve semua
query param yang sudah ada (status, severity, search, dll) — hanya mengganti
`range`.

Backend memakai `DateRangeFilter`:

- `DateRangeFilter::resolve($request)` → `[from, to, preset]`
- `DateRangeFilter::apply($query, $range)` → `where created_at >= from AND <= to`

Stat cards di data-audits/sessions tetap global (cached), hanya tabel yang
ter-filter rentang waktu.

## Proteksi

- Dashboard gate default `local_only => true` + `allowed_ips` (`127.0.0.1`, `::1`)
- Semua POST butuh CSRF token
- `ConfigWriterService::write()` hanya menerima key whitelist (dari controller),
  tak ada path traversal / arbitrary config write
- Live events endpoint read-only, tanpa mutation