# Middleware WAF & Karantina IP (Fail2Ban)

Middleware `RequestThreatScanner` bertindak sebagai gerbang terdepan untuk memeriksa request HTTP sebelum mencapai controller aplikasi.

---

## 1. Alur Pipeline Inspeksi Middleware

Setiap request yang masuk dievaluasi berurutan dengan alur berikut:

```text
Request HTTP Masuk
       │
       ▼
[1. Metode Terlarang]      ──> Blokir TRACE / TRACK instan (405 Method Not Allowed)
       │
       ▼
[2. Pengecekan Karantina]  ──> Jika IP masuk karantina, tolak instan HTTP 429
                               (Nol CPU regex, menghemat resource server saat DDoS)
       │
       ▼
[3. Request Flood Limiter] ──> Counter atomic O(1). Jika melebihi kuota, auto-jail & tolak 429
       │
       ▼
[4. Fast-Path Bypass]      ──> Lewati regex scan jika request GET/HEAD tanpa body & tanpa query
       │
       ▼
[5. Path Recon & Bot UA]   ──> Deteksi probe file sensitif (.env, .git) dan tool scanning
       │
       ▼
[6. Pemindaian Payload]    ──> Scan rekursif parameter & body terhadap SQLi, XSS, Traversal, RCE
       │
       ▼
[7. Lolos ke Aplikasi]     ──> Teruskan ke middleware berikutnya / Controller Laravel
```

---

## 2. Karantina IP Aktif (Fail2Ban-Style)

Ketika klien terbukti melakukan serangan kritis (misal SQL Injection atau Remote Code Execution), sistem otomatis mengisolasi alamat IP tersebut ke dalam daftar karantina:

- **Penolakan Instan**: Request berikutnya dari IP terisolasi langsung diputus di baris awal middleware dengan respon HTTP 429 tanpa menjalankan evaluasi regex berat atau query database.
- **Dukungan Durabilitas Ganda**: Secara default status karantina disimpan di cache. Dengan mengaktifkan `persist_to_database => true` pada file konfigurasi, data karantina dicadangkan ke tabel database `security_quarantines` agar tetap bertahan meski cache di-clear atau server direstart.
- **Whitelist Proteksi**: IP localhost (`127.0.0.1`, `::1`) dan proxy tepercaya yang terdaftar pada konfigurasi tidak akan pernah masuk karantina secara tidak sengaja.

### Manajemen Karantina Programatik (Facade)

```php
use Mixudev\SecurityDefense\Support\Facades\SecurityDefense;

// Cek status karantina
$isJailed = SecurityDefense::quarantine()->isQuarantined('198.51.100.22');

// Masukkan IP ke karantina secara manual (IP, durasi dalam detik, alasan)
SecurityDefense::quarantine()->jail('198.51.100.22', 3600, 'Blokir manual oleh tim NOC');

// Bebaskan IP dari karantina
SecurityDefense::quarantine()->pardon('198.51.100.22');

// Dapatkan rincian alasan dan sisa waktu karantina
$details = SecurityDefense::quarantine()->getDetails('198.51.100.22');
```

---

## 3. Proteksi Request Flood

Melindungi endpoint website dari scraper agresif dan serangan flooding layer 7 menggunakan penghitung atomik berkinerja tinggi:

- Parameter `max_requests_per_second` (default 200 req/dtk per IP).
- Jika sebuah IP terus melampaui batas yang diizinkan selama beberapa jendela waktu, middleware langsung memutus koneksi (HTTP 429) dan mengarantina IP tersebut.

---

## 4. Keamanan Anti-ReDoS & Bounded Execution

- String masukan dipotong secara aman jika melampaui `hardening.max_inspection_length` (default 4096 karakter) sebelum dicek regex.
- Rekursi array dibatasi maksimal 5 tingkat kedalaman (`hardening.max_traversal_depth`) untuk mengamankan memori server dari stack overflow.
