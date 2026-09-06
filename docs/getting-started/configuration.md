# Referensi Konfigurasi

Referensi lengkap file `config/security-defense.php`.

Struktur arsitektur package menempatkan seluruh pengaturan saklar aktivasi (`enabled` => `true`/`false`), batas threshold, bobot skoring, dan parameter proteksi di dalam file konfigurasi ini. File `.env` dikhususkan untuk menyimpan data rahasia/kredensial API eksternal.

---

## Opsi Utama

| Kunci Konfigurasi | Nilai Default | Deskripsi |
|---|---|---|
| `enabled` | `true` | Saklar global untuk seluruh fungsi deteksi, WAF middleware, dan pengiriman alert. |
| `cache_store` | `null` | Store cache yang digunakan untuk sliding window counter, dedup, dan karantina. Jika null, menggunakan default cache Laravel. |
| `cache_prefix` | `'security_defense:'` | Prefix namespace untuk semua key cache yang dibuat oleh package. |

---

## Hardening & Self-Defense (`hardening`)

Melindungi package dari eksploitasi Denial-of-Service terhadap resource server.

| Kunci Konfigurasi | Nilai Default | Deskripsi |
|---|---|---|
| `max_inspection_length` | `4096` | Batas panjang string maksimum yang dievaluasi regex. Karakter selebihnya dipotong aman untuk mencegah ReDoS. |
| `max_traversal_depth` | `5` | Batas kedalaman rekursi array input untuk mencegah memory exhaustion. |
| `alert_rate_limit.enabled` | `true` | Mengaktifkan pembatasan rate penulisan alert ke database. |
| `alert_rate_limit.max_alerts_per_minute` | `60` | Jumlah maksimal alert yang dapat disimpan ke database per menit untuk melindungi disk dari storming. |
| `max_alert_metadata_size` | `16384` | Batas ukuran JSON metadata alert dalam satuan byte sebelum dilakukan pemotongan aman. |

---

## Compound Threat Scoring (`detection.scoring`)

Menghitung akumulasi risiko dari berbagai jenis serangan berbeda terhadap target yang sama.

| Kunci Konfigurasi | Nilai Default | Deskripsi |
|---|---|---|
| `enabled` | `true` | Mengaktifkan engine kalkulasi skor gabungan. |
| `threshold` | `100` | Batas akumulasi skor untuk menerbitkan alert kritis `compound_threat`. |
| `window` | `900` | Jendela waktu akumulasi skor (15 menit) dalam detik. |
| `max_records` | `50` | Batas maksimal histori record serangan per entitas dalam cache. |
| `weights` | Array | Bobot skor per vektor serangan (`payload_injection: 50`, `credential_stuffing: 45`, `brute_force: 35`, dll). |

---

## Aturan Deteksi (`detection.rules`)

| Aturan | Kunci | Ambang Default | Window | Severity |
|---|---|---|---|---|
| Brute Force | `brute_force` | 10 kegagalan | 60 detik | `high` |
| Credential Stuffing | `credential_stuffing` | 8 identifier | 120 detik | `critical` |
| Distributed Spray | `distributed_spray` | 5 IP | 300 detik | `high` |
| Rate Limit Bypass | `rate_limit_bypass` | 15 rotasi header | 60 detik | `medium` |
| Payload Injection | `payload_injection` | Deteksi instan | Seketika | `critical` |
| Impossible Travel | `impossible_travel` | > 900 km/jam | Antar login | `high` |
| Path Reconnaissance | `path_reconnaissance` | 5 probe | 120 detik | `high` |
| User Agent Anomaly | `user_agent_anomaly` | Signature match | Seketika | `high` |

---

## Middleware & Karantina IP (`middleware`)

| Kunci Konfigurasi | Nilai Default | Deskripsi |
|---|---|---|
| `payload_scanner.enabled` | `true` | Mengaktifkan inspeksi payload HTTP request. |
| `payload_scanner.action` | `'block'` | Tindakan saat deteksi ancaman: `'block'` (HTTP 403) atau `'log_only'`. |
| `payload_scanner.scan_empty_requests` | `false` | Fast-path: lewati scanning regex pada GET/HEAD tanpa body & tanpa query params. |
| `payload_scanner.excluded_paths` | `[]` | URI path yang dikecualikan dari scanning. |
| `detection.rules.payload_injection.patterns.ssrf_localhost` | `false` | Deteksi SSRF `localhost`/`127.0.0.1`. Default `false` karena app sah mengirim ke origin sendiri (mis. telemetry `http://localhost:8000/`). Aktifkan (`true`) hanya di deployment strict tanpa traffic loopback.
| `request_flood.enabled` | `true` | Mengaktifkan proteksi flood per-IP berbasis counter atomic O(1). |
| `request_flood.max_requests_per_second` | `200` | Batas maksimum request per detik sebelum dikembalikan 429 dan dimasukkan karantina. |
| `quarantine.enabled` | `true` | Mengaktifkan sistem Fail2Ban IP Quarantine. |
| `quarantine.duration` | `900` | Durasi karantina IP dalam detik (15 menit). |
| `quarantine.auto_jail_on_critical` | `true` | Mengisolasi IP secara otomatis saat mencoba serangan kritis (SQLi, RCE). |
| `quarantine.persist_to_database` | `false` | Menyimpan status karantina ke tabel `security_quarantines` agar tahan cache flush. |
| `quarantine.whitelist` | `['127.0.0.1', '::1']` | Daftar IP yang tidak boleh dikarantina. |

---

## Channel Notifikasi (`alerts`)

Semua channel diaktifkan atau dinonaktifkan lewat config ini. Credential dibaca dari `.env`.

| Channel | Switch Aktif di Config | Variabel Kredensial di `.env` |
|---|---|---|
| Database | `'database' => ['enabled' => true]` | Selalu aktif (tabel default `security_alerts`) |
| Telegram | `'telegram' => ['enabled' => true]` | `SECURITY_TELEGRAM_BOT_TOKEN`, `SECURITY_TELEGRAM_CHAT_ID` |
| Discord | `'discord' => ['enabled' => true]` | `SECURITY_DISCORD_WEBHOOK` |
| Webhook | `'webhook' => ['enabled' => false]` | `SECURITY_WEBHOOK_URL`, `SECURITY_WEBHOOK_SECRET` |
| Mail | `'mail' => ['enabled' => false]` | `SECURITY_ALERT_EMAIL` |
| Queue | `'queue' => ['enabled' => false]` | `connection`, `queue_name` |
