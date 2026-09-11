# 02. Panduan Konfigurasi

File konfigurasi utama terletak di `config/security-defense.php` setelah instalasi dijalankan.

---

## 1. Mekanisme Konfigurasi & Runtime Overrides

Package mendukung dua cara pengaturan:

1. **File Konfigurasi Utama (`config/security-defense.php`)**:
   Dikelola oleh developer sebagai baseline bawaan aplikasi.
2. **Runtime Overrides (`config/security-defense-overrides.php`)**:
   Dibuat secara otomatis saat Anda mengubah pengaturan melalui dashboard UI atau perintah CLI (seperti flag `--with-opaque-path`). Nilai pada file overrides akan menimpa file konfigurasi utama tanpa perlu mengedit file package secara manual.

---

## 2. Tabel Ringkasan Opsi Konfigurasi Utama

### A. WAF & Proteksi Request
| Kunci | Tipe | Default | Keterangan |
|---|---|---:|---|
| `waf.enabled` | bool | `true` | Mengaktifkan scanning input otomatis pada setiap request HTTP |
| `waf.block_mode` | string | `'block'` | `'block'` (langsung tolak 403) atau `'monitor'` (hanya catat log) |
| `waf.rules.sqli` | bool | `true` | Deteksi pola serangan SQL Injection |
| `waf.rules.xss` | bool | `true` | Deteksi skrip cross-site scripting berbahaya |
| `waf.rules.traversal` | bool | `true` | Deteksi path directory traversal (`../`, `..\`) |
| `waf.rules.command_injection` | bool | `true` | Deteksi injeksi perintah sistem OS shell |
| `middleware.user_agent_anomaly.enabled` | bool | `true` | Deteksi client anomali (scanner SQLMap, Nikto, Gobuster) |
| `middleware.user_agent_anomaly.block_headless_clients` | bool | `false` | Blokir browser headless otomatis (Puppeteer, Playwright non-human) |

### B. Dashboard & Akses Opaque
| Kunci | Tipe | Default | Keterangan |
|---|---|---:|---|
| `dashboard.enabled` | bool | `true` | Mengaktifkan endpoint dashboard internal |
| `dashboard.path` | string | `'security-defense'` | Rute portal gate awal untuk verifikasi |
| `dashboard.local_only` | bool | `true` | Membatasi akses strictly hanya untuk IP loopback (`127.0.0.1`, `::1`) dan `APP_ENV=local` |
| `dashboard.allowed_ips` | array | `['127.0.0.1', '::1']` | Daftar IP yang diizinkan mengakses di mode lokal |
| `dashboard.opaque_path.enabled` | bool | `true` (default pabrik) | Menyamarkan rute dashboard menjadi token capability acak sekali pakai |
| `dashboard.opaque_path.ttl_seconds` | int | `60` | Masa berlaku URL capability sebelum hangus (detik, minimal 10s) |
| `dashboard.key` | string | `env('SECURITY_DEFENSE_KEY')` | Kunci khusus enkripsi dashboard. Jika kosong, diturunkan otomatis via HKDF dari `APP_KEY` |

### C. Mesin Deteksi & Karantina IP Otomatis
| Kunci | Tipe | Default | Keterangan |
|---|---:|---|
| `detection.enabled` | bool | `true` | Mengaktifkan seluruh mesin deteksi anomali |
| `detection.scoring.threshold` | int | `100` | Skor agregat ancaman untuk memicu alert compound threat |
| `detection.scoring.window` | int | `900` | Jendela akumulasi skor ancaman (detik = 15 menit) |
| `detection.quarantine.enabled` | bool | `true` | Otomatis mengisolasi IP yang melakukan serangan kritis |
| `detection.quarantine.duration` | int | `900` | Durasi karantina dalam detik (default 15 menit) |
| `detection.quarantine.auto_jail_on_critical` | bool | `true` | Langsung karantina IP bila terdeteksi serangan level critical |
| `detection.quarantine.response_status` | int | `429` | HTTP status code untuk klien yang dikarantina (429 atau 403) |
| `detection.quarantine.whitelist` | array | `['127.0.0.1', '::1']` | Daftar IP yang kebal dari pemblokiran karantina otomatis |
| `hardening.alert_rate_limit.max_alerts_per_minute` | int | `60` | Pembatasan jumlah alert per menit untuk mencegah badai log |
| `hardening.max_inspection_length` | int | `4096` | Panjang maksimum inspeksi per field (anti-ReDoS) |

### D. Saluran Notifikasi & Alert
| Kunci | Tipe | Default | Keterangan |
|---|---|---:|---|
| `alerts.default_channel` | string | `'log'` | Saluran utama: `'log'`, `'telegram'`, atau `'webhook'` |
| `alerts.telegram.enabled` | bool | `false` | Mengaktifkan integrasi bot Telegram |
| `alerts.telegram.bot_token` | string | `env(...)` | Bot Token dari @BotFather |
| `alerts.telegram.chat_id` | string | `env(...)` | ID chat / channel penerima notifikasi |
| `alerts.telegram.interactive.enabled` | bool | `true` | Mengaktifkan tombol interaktif di Telegram (Pardon/Whitelist IP langsung dari chat) |
| `alerts.webhook.enabled` | bool | `false` | Mengirim payload insiden ke endpoint SIEM eksternal |
| `alerts.webhook.url` | string | `env(...)` | URL target webhook penerima alert |
| `alerts.webhook.secret` | string | `env(...)` | Rahasia penandatanganan HMAC signature (`X-Security-Defense-Signature`) |

### E. CSP Armor & Keamanan Header
| Kunci | Tipe | Default | Keterangan |
|---|---|---:|---|
| `csp_armor.enabled` | bool | `false` | Menyuntikkan header Content-Security-Policy (CSP) ketat pada respons |
| `csp_armor.report_only` | bool | `true` | Mode pelaporan saja (tidak memutus fungsi skrip host sebelum diuji) |
