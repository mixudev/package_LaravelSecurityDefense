# Rancangan Ekspansi Sistem: Security Defense — Generasi Berikutnya

Dokumen ini adalah rancangan teknis dari perspektif Lead Programmer untuk memperluas
`mixudev/security-defense` melampaui batas ancaman server menuju perlindungan menyeluruh
yang meliputi ancaman dari sisi klien, device korban, dan sesi yang telah dikompromikan.

---

## 1. Penilaian Jujur Sistem Saat Ini

Sistem yang ada sudah sangat solid untuk kategori ancaman **server-side dan network-level**:

```
KUAT:
  + WAF payload scanning (SQLi, XSS, RCE, LFI)            -- layer 7
  + Brute force & credential stuffing detection            -- pola login
  + Impossible travel (Haversine, cache-lock TOCTOU-safe)  -- geolokasi
  + Compound threat scoring (multi-vektor korelasi)        -- kecerdasan
  + Fail2Ban IP quarantine (O(1) pengecekan, cache+DB)     -- respons aktif
  + Zero-leakage sanitizer (rekursif, depth-bounded)       -- privasi data
  + Request flood limiter (atomic counter)                 -- DDoS L7

CELAH BESAR YANG BELUM DISENTUH:
  - Session hijacking dari device korban yang terinfeksi malware
  - Cookie theft / XSS session stealing di browser korban
  - Anomali perilaku sesi yang sudah terautentikasi (post-login)
  - Deteksi akun yang sudah dikompromikan lalu dipakai perlahan
  - Header fingerprint kontradiktif (TLS fingerprint vs user-agent)
  - Business logic abuse (bukan injection, tapi pola perilaku abnormal)
  - Kebocoran data via response manipulation / API scraping terautentikasi
  - Ancaman insider: admin yang mencuri data perlahan-lahan
  - Deteksi perangkat baru / lingkungan browser yang berubah tiba-tiba
```

---

## 2. Model Ancaman Baru Yang Harus Dihadapi

### 2.1 Skenario: Korban Login Dari Device Terinfeksi Malware

```text
[Device korban terinfeksi infostealer]
         │
         ▼ Malware mencuri session cookie dari browser
[Penyerang mendapat session cookie yang valid]
         │
         ▼ Replay cookie dari IP / device berbeda
[Server menerima request VALID karena cookie autentik]
         │
         ▼ Laravel tidak tahu ini bukan user asli
[SISTEM SAAT INI BUTA TOTAL -- tidak ada yang ter-trigger]
```

**Masalah inti**: Semua rule yang ada bekerja pada level *unauthenticated threats*.
Begitu session valid dipegang penyerang, sistem kita tidak melihat apa-apa.

### 2.2 Skenario: Insider Threat / Admin Jahat

```text
[Admin sah login dari lokasi benar, device benar]
         │
         ▼ Mulai export data sedikit-sedikit (bulk query terautentikasi)
         ▼ Akses resource yang bukan tugasnya
         ▼ Mengubah konfigurasi sensitif di jam tengah malam
[SISTEM SAAT INI: tidak ada yang terdeteksi]
```

### 2.3 Skenario: Automated Scraping Post-Login

```text
[Bot berhasil login menggunakan akun yang bocor / dibeli darkweb]
         │
         ▼ Melakukan ratusan request API terautentikasi per menit
         ▼ Bukan injection, bukan brute force -- hanya akses normal tapi cepat
[SISTEM SAAT INI: tidak terdeteksi karena rule tidak memonitor sesi aktif]
```

---

## 3. Arsitektur Ekspansi: Session Intelligence Layer

### 3.1 Rancangan Modul Baru

```text
ARSITEKTUR GENERASI BERIKUTNYA:

Lapisan 0: Active Defense (SUDAH ADA)
  └── IP Quarantine + Request Flood Limiter

Lapisan 1: Preventive WAF (SUDAH ADA)
  └── RequestThreatScanner (8 rules)

Lapisan 2: Ingested Telemetry Intelligence (SUDAH ADA)
  └── AnomalyDetector + ThreatScoringEngine

[====== EKSPANSI MULAI DI SINI ======]

Lapisan 3: Session Behavioral Intelligence (BARU)
  ├── SessionFingerprintRule     -- deteksi session takeover
  ├── BehavioralVelocityRule     -- kecepatan aksi post-login abnormal
  ├── PrivilegeAbuseRule         -- pola akses resource tidak wajar
  ├── DataExfiltrationRule       -- volume respons abnormal (API scraping)
  └── NightShiftAnomalyRule      -- aktivitas diluar jam pola normal akun

Lapisan 4: Client Environment Intelligence (BARU)
  ├── TlsJa3FingerprintRule      -- fingerprint TLS klien vs user-agent
  ├── HttpHeaderConsistencyRule  -- kontradiksi antar header (bot detection)
  ├── DeviceEnrollmentRule       -- perangkat baru / lingkungan browser baru
  └── BrowserEntropyRule         -- entropi header browser (headless detection)

Lapisan 5: Response-Side Monitoring (BARU)
  ├── ResponseVolumeMonitor      -- respons byte yang tidak wajar besar
  └── SensitiveEndpointAccessLog -- pencatatan akses endpoint sensitif

Lapisan 6: Adaptive Response (BARU)
  ├── SoftChallenge              -- tantangan soft (CAPTCHA / re-auth prompt)
  ├── SessionDemotion            -- downgrade hak sesi secara paksa
  ├── StepUpAuth trigger         -- sinyal ke sistem auth untuk minta verifikasi ulang
  └── AccountFreezeSignal        -- sinyal ke aplikasi untuk kunci akun sementara
```

---

## 4. Rancangan Detail Setiap Modul Baru

---

### 4.1 SESSION FINGERPRINT RULE
**File**: `src/Rules/SessionFingerprintRule.php`
**Tujuan**: Mendeteksi sesi yang dibajak — ketika session cookie yang sama digunakan
dari lingkungan yang berbeda secara signifikan dari login pertama.

**Data yang direkam saat login**:
- IP subnet (/24 untuk toleransi DHCP rotation)
- User-Agent hash
- Accept-Language header
- Accept-Encoding header
- Timezone offset (dari header atau JS payload)
- Screen fingerprint hash (opsional, dari JS beacon)

**Logika deteksi**:
```
Saat request terautentikasi masuk:
  fingerprint_saat_ini = hash(IP_subnet + UA + Accept-Language + Accept-Encoding)
  fingerprint_saat_login = ambil dari cache/session

  jika fingerprint berubah > threshold kontradiksi:
    --> HIGH/CRITICAL: session_hijack_suspected

Contoh yang pasti mencurigakan:
  - Login dari Chrome Windows, request berikutnya dari curl/Python
  - Login dari ID, request dari DE dalam 30 menit (sudah ditangani ImpossibleTravel,
    tapi SessionFingerprint menangkap perubahan UA sekalipun IP nya dekat)
  - User-Agent berubah total di tengah sesi aktif
```

**Integrasi**: Perlu middleware post-authentication, bukan WAF awal.
Middleware ini berjalan setelah Laravel auth middleware.

---

### 4.2 BEHAVIORAL VELOCITY RULE
**File**: `src/Rules/BehavioralVelocityRule.php`
**Tujuan**: Mendeteksi kecepatan interaksi yang tidak manusiawi dari akun terautentikasi.

**Bukan brute force** — akun sudah login. Ini tentang perilaku setelah login.

**Metrik yang diukur**:
- Request per menit per authenticated user_id (bukan per IP)
- Jumlah unique endpoint yang dikunjungi per menit
- Pola waktu antar request (manusia: variabel 1-5 detik, bot: konstan <100ms)
- Rasio POST vs GET yang abnormal

**Threshold contoh**:
```
normal_human_rpm: 20-60 rpm (termasuk resource loading)
suspicious_rpm: > 120 rpm (otomasi ringan / skrip)
critical_rpm: > 300 rpm (bot agresif)
```

**Kenapa penting**: Bot yang sudah punya akun valid bisa scrape seluruh database
tanpa trigger rule manapun karena semua request-nya "sah".

---

### 4.3 PRIVILEGE ABUSE RULE
**File**: `src/Rules/PrivilegeAbuseRule.php`
**Tujuan**: Mendeteksi akses resource yang tidak konsisten dengan pola historis akun.

**Membutuhkan input dari aplikasi host** tentang:
- Role/level akun (`eventType: 'ResourceAccess'`, `metadata: ['resource' => 'admin_users', 'method' => 'export']`)

**Logika**:
```
Aplikasi host mengirim telemetri:
  SecurityDefense::record([
    'ip' => ...,
    'identifier' => auth()->id(),
    'eventType' => 'ResourceAccess',
    'metadata' => [
      'resource_type' => 'user_export',
      'record_count' => 5000,
      'user_role' => 'editor',  // bukan admin
    ]
  ]);

Rule mendeteksi:
  - editor mengakses bulk export > 1000 records
  - akun mengakses 10+ resource types berbeda dalam 5 menit
  - akses ke /admin/* dari akun non-admin (harusnya 403, tapi jika 200: anomali)
```

---

### 4.4 DATA EXFILTRATION RULE
**File**: `src/Rules/DataExfiltrationRule.php`
**Tujuan**: Mendeteksi pencurian data via akses API/endpoint yang terautentikasi
dengan volume respons abnormal tinggi.

**Pendekatan**: Monitor RESPONSE size, bukan request size.

**Implementasi teknis**:
Middleware baru `ResponseSizeMonitor` yang membaca `Content-Length` atau ukuran
response body aktual dan mengirimkannya sebagai telemetri:

```php
// src/Middleware/ResponseSizeMonitor.php
// Berjalan setelah response dibentuk (terminate middleware)
public function terminate(Request $request, Response $response): void
{
    if (! auth()->check()) return;

    $size = strlen($response->getContent());
    SecurityDefense::record([
        'ip' => $request->ip(),
        'identifier' => (string) auth()->id(),
        'eventType' => 'ResponseSizeEvent',
        'metadata' => [
            'endpoint' => $request->path(),
            'method' => $request->method(),
            'response_size_bytes' => $size,
            'status_code' => $response->getStatusCode(),
        ]
    ]);
}
```

**Deteksi**:
```
Dalam window 10 menit per user:
  total_bytes_diterima > 50MB --> suspicious
  total_bytes_diterima > 200MB --> critical (data exfiltration)
  single_response > 10MB --> flag (bulk export tidak lazim)
```

---

### 4.5 DEVICE ENROLLMENT RULE
**File**: `src/Rules/DeviceEnrollmentRule.php`
**Tujuan**: Mendeteksi login dari perangkat/browser yang belum pernah digunakan
akun tersebut sebelumnya.

Ini mirip ImpossibleTravel, tapi fokus pada **sidik jari perangkat**, bukan lokasi.

**Fingerprint perangkat (tanpa JavaScript)**:
```
device_fingerprint = sha256(
    User-Agent
    + Accept-Language
    + Accept-Encoding
    + Accept (MIME types)
    + Sec-CH-UA (Client Hints jika ada)
)
```

**Dengan JavaScript beacon (opsional, opt-in)**:
Aplikasi host bisa kirim data tambahan via API:
```json
{
  "screen_resolution": "1920x1080",
  "timezone": "Asia/Jakarta",
  "color_depth": 24,
  "platform": "Win32",
  "hardware_concurrency": 8
}
```

**Logika**:
```
Saat login sukses pertama dari device baru:
  Jika akun sudah punya histori device:
    --> LOW: new_device_login (informational, kirim notifikasi ke user)
  
  Jika akun tidak punya histori sama sekali:
    --> Simpan sebagai device pertama yang terpercaya

  Jika device baru DAN lokasi berbeda dari biasanya:
    --> HIGH: new_device_foreign_location (korelasi dengan ImpossibleTravel)
```

---

### 4.6 HTTP HEADER CONSISTENCY RULE
**File**: `src/Rules/HttpHeaderConsistencyRule.php`
**Tujuan**: Mendeteksi bot/tool otomatis yang menyamar menggunakan User-Agent browser
nyata tetapi gagal mensimulasikan header browser yang konsisten.

**Kontradiksi yang dicurigai**:
```
UA: "Mozilla/5.0 ... Chrome/120" tapi TIDAK ADA:
  - Accept-Language header
  - Accept-Encoding header
  - Sec-Fetch-* headers (ada di semua browser modern)
  - Referer di request halaman dalam (bukan direct)

UA: Firefox tapi kirim header Sec-CH-UA (hanya ada di Chromium)
UA: Chrome Mobile tapi Accept berisi "text/html" only (bukan MIME prioritas mobile)
UA: Desktop browser tapi Content-Type: application/json di semua GET
```

**Ini mendeteksi**: `requests` library Python, Playwright headless yang tidak
dikonfigurasi dengan baik, curl dengan User-Agent palsu.

---

### 4.7 TLS JA3 FINGERPRINT RULE
**File**: `src/Rules/TlsJa3FingerprintRule.php`
**Tujuan**: Mengidentifikasi klien dari fingerprint negosiasi TLS — fingerprint ini
TIDAK BISA DIPALSUKAN oleh tool biasa karena dibentuk di level TCP/TLS.

**Cara kerja**:
JA3 hash dibentuk dari:
- TLS version yang ditawarkan
- Cipher suites yang didukung klien
- Extension TLS yang dikirim
- Elliptic curves yang didukung

Hasilnya adalah hash 32 karakter yang berbeda untuk setiap jenis klien:
```
Chrome 120:  hash tertentu yang konsisten
Firefox 120: hash berbeda
curl 7.x:    hash yang khas (dikenali database JA3)
Python requests: hash yang khas
Scrapy:      hash yang khas
```

**Implementasi di Laravel**:
Membutuhkan data dari server Nginx/Apache yang meneruskan JA3 ke header:
```nginx
# nginx.conf
ssl_preread_alpn_protocols on;
# Gunakan nginx-module-ja3 atau haproxy untuk ekstrak JA3
proxy_set_header X-JA3-Fingerprint $ssl_ja3;
```

Package kemudian membaca:
```php
$ja3 = $request->header('X-JA3-Fingerprint');
```

**Aturan**:
```
jika JA3 ada di daftar fingerprint tool berbahaya yang diketahui:
  --> MEDIUM: suspicious_tls_client

jika JA3 tidak konsisten dengan User-Agent yang diklaim:
  (User-Agent Chrome tapi JA3-nya adalah Python requests)
  --> HIGH: tls_fingerprint_mismatch
```

---

### 4.8 NIGHT SHIFT ANOMALY RULE
**File**: `src/Rules/NightShiftAnomalyRule.php`
**Tujuan**: Mendeteksi aktivitas signifikan yang terjadi diluar jam aktivitas normal
akun — indikasi kuat bahwa akun sedang dioperasikan oleh pihak lain (malware/penyerang).

**Logika**:
```
Bangun model aktivitas normal per akun:
  {jam_pertama_aktif: 08, jam_terakhir_aktif: 22, timezone: "Asia/Jakarta"}

Saat request masuk:
  jam_lokal_user = utc_now + user_timezone_offset

  jika jam_lokal_user antara 01:00 - 05:00:
    DAN akun ini tidak pernah aktif di jam ini sebelumnya:
    DAN request melibatkan aksi sensitif (export, delete, config change):
      --> HIGH: suspicious_off_hours_activity
```

**Keterbatasan yang jujur**: Bergantung pada timezone yang benar dari user.
Jika user tidak menyediakan timezone, tidak akurat. Default: gunakan timezone server.

---

### 4.9 MODUL ADAPTIVE RESPONSE

Ini adalah bagian yang paling penting dan paling sulit — **apa yang sistem lakukan**
setelah ancaman terdeteksi pada sesi yang sudah terautentikasi.

Sistem TIDAK BISA langsung logout paksa karena:
1. Itu tugas sistem auth, bukan tugas package ini (prinsip decoupling)
2. False positive akan sangat mengganggu user asli

**Solusi: Graduated Response System**

```text
Level Respons:

LEVEL 1 -- Observasi (threat score: 20-40)
  ├── Catat alert ke database
  ├── Tandai sesi sebagai "under surveillance"
  └── Kirim notifikasi ke admin

LEVEL 2 -- Soft Challenge (threat score: 40-70)
  ├── Set flag di cache: "session:{session_id}:challenge_required = true"
  ├── Aplikasi host memantau flag ini via helper facade
  └── Tampilkan CAPTCHA / re-enter password halaman berikutnya
      (keputusan tampil ada di aplikasi host, bukan package)

LEVEL 3 -- Session Demotion (threat score: 70-100)
  ├── Set flag: "session:{session_id}:demoted = true"
  ├── Batasi akses ke endpoint sensitif (aplikasi host cek flag ini)
  └── Kirim alert CRITICAL ke semua channel

LEVEL 4 -- Force Invalidation Signal (threat score: > 100 atau compound)
  ├── Dispatch event Laravel: SecuritySessionCompromised
  ├── Aplikasi host listening ke event ini untuk logout paksa
  └── Quarantine IP + block device fingerprint
```

**Implementasi Facade-nya**:
```php
// Di middleware aplikasi host (contoh usage)
if (SecurityDefense::session()->isChallengeRequired(session()->getId())) {
    return redirect()->route('security.challenge');
}

if (SecurityDefense::session()->isDemoted(session()->getId())) {
    abort(403, 'Akses sementara dibatasi karena aktivitas mencurigakan.');
}
```

---

## 5. Struktur File Baru Yang Perlu Dibuat

```text
src/
├── Rules/                              (existing)
│   ├── SessionFingerprintRule.php      [BARU]
│   ├── BehavioralVelocityRule.php      [BARU]
│   ├── PrivilegeAbuseRule.php          [BARU]
│   ├── DataExfiltrationRule.php        [BARU]
│   ├── DeviceEnrollmentRule.php        [BARU]
│   ├── HttpHeaderConsistencyRule.php   [BARU]
│   ├── NightShiftAnomalyRule.php       [BARU]
│   └── TlsJa3FingerprintRule.php       [BARU -- butuh infrastruktur server]
│
├── Middleware/                         (existing)
│   ├── RequestThreatScanner.php        (existing)
│   ├── AuthenticatedSessionScanner.php [BARU -- post-auth middleware]
│   └── ResponseSizeMonitor.php         [BARU -- terminate middleware]
│
├── Services/
│   └── SessionRiskService.php          [BARU -- adaptive response state manager]
│
├── Events/
│   ├── ThreatDetected.php              (existing)
│   ├── SecurityAlertCreated.php        (existing)
│   ├── SecurityAlertResolved.php       (existing)
│   └── SecuritySessionCompromised.php  [BARU -- sinyal ke aplikasi host]
│
└── Contracts/
    └── SessionRiskInterface.php        [BARU]
```

---

## 6. Perubahan Database yang Dibutuhkan

### Tabel baru: `security_device_profiles`
```sql
CREATE TABLE security_device_profiles (
    id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    identifier_hash VARCHAR(64)  NOT NULL,  -- sha256(user_id atau email)
    device_hash     VARCHAR(64)  NOT NULL,  -- sha256(UA+headers combination)
    first_seen_at   TIMESTAMP    NOT NULL,
    last_seen_at    TIMESTAMP    NOT NULL,
    seen_count      INT UNSIGNED DEFAULT 1,
    ip_hash         VARCHAR(64),            -- sha256(IP subnet /24)
    country         VARCHAR(8),
    trusted         BOOLEAN DEFAULT FALSE,
    metadata        JSON,
    INDEX idx_identifier (identifier_hash),
    UNIQUE KEY uk_device (identifier_hash, device_hash)
);
```

### Tabel baru: `security_session_risks`
```sql
CREATE TABLE security_session_risks (
    id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    session_id_hash VARCHAR(64)  NOT NULL UNIQUE,
    risk_score      INT UNSIGNED DEFAULT 0,
    risk_level      ENUM('safe','monitored','challenged','demoted','compromised') DEFAULT 'safe',
    flags           JSON,        -- {challenge_required, demoted, reasons[]}
    created_at      TIMESTAMP    DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP    DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    expires_at      TIMESTAMP,
    INDEX idx_session (session_id_hash)
);
```

---

## 7. Perubahan Config yang Dibutuhkan

Tambahan bagian baru di `config/security-defense.php`:

```php
'session_intelligence' => [
    'enabled' => true,

    'session_fingerprint' => [
        'enabled' => true,
        'tolerance' => 2,    // berapa kontradiksi header ditoleransi sebelum alert
    ],

    'behavioral_velocity' => [
        'enabled' => true,
        'window' => 60,
        'max_rpm' => 120,    // request per minute per auth user
        'critical_rpm' => 300,
    ],

    'data_exfiltration' => [
        'enabled' => true,
        'window' => 600,     // 10 menit
        'max_total_bytes' => 52428800,   // 50MB
        'max_single_response_bytes' => 10485760, // 10MB
    ],

    'night_shift' => [
        'enabled' => false,  // opt-in, butuh data timezone user
        'sensitive_hours_start' => 1,
        'sensitive_hours_end' => 5,
    ],

    'device_enrollment' => [
        'enabled' => true,
        'notify_on_new_device' => true,
    ],
],

'adaptive_response' => [
    'enabled' => true,
    'challenge_threshold' => 40,    // score sesi >= ini: minta re-verify
    'demotion_threshold' => 70,     // score sesi >= ini: batasi akses
    'compromised_threshold' => 100, // score sesi >= ini: dispatch event
],
```

---

## 8. Urutan Implementasi yang Disarankan

Berdasarkan nilai vs kompleksitas:

```
FASE 1 (Nilai tinggi, kompleksitas rendah -- bisa langsung):
  1. HttpHeaderConsistencyRule  -- tidak perlu data baru, cukup baca header
  2. BehavioralVelocityRule     -- sliding window + counter, pola sama dengan BruteForce
  3. DeviceEnrollmentRule       -- simpan hash device di cache dulu, DB nanti
  4. NightShiftAnomalyRule      -- butuh data timezone dari host, opt-in

FASE 2 (Nilai sangat tinggi, kompleksitas medium):
  5. SessionFingerprintRule + AuthenticatedSessionScanner middleware
  6. DataExfiltrationRule + ResponseSizeMonitor middleware
  7. SessionRiskService + adaptive response state (flag cache)
  8. SecuritySessionCompromised event + Facade session() accessor

FASE 3 (Nilai tinggi, butuh infrastruktur server):
  9. TlsJa3FingerprintRule -- butuh modul nginx/haproxy tambahan
  10. PrivilegeAbuseRule   -- butuh telemetri dari aplikasi host (tugas user)

FASE 4 (Jangka panjang, butuh ML/statistik):
  11. BehavioralBaselineRule -- bangun model perilaku normal per akun dari data historis
  12. AnomalyScoreRule       -- simpangan standar dari baseline sebagai trigger
```

---

## 9. Pertimbangan dan Batasan yang Jujur

### Yang BISA dilakukan package ini:
- Mendeteksi dan memberi sinyal semua ancaman di atas
- Menyimpan state dalam cache dan database
- Mendispatch event Laravel yang dapat didengarkan host
- Menyediakan facade/helper untuk dicek dari host

### Yang TIDAK BOLEH dilakukan package ini (prinsip decoupling):
- Logout paksa user (tugas sistem auth host)
- Hapus session secara langsung (milik Laravel session driver)
- Tampilkan CAPTCHA secara paksa (milik view/controller host)
- Kirim email notifikasi ke user akhir (bukan ke admin, itu urusan auth)

### Tantangan teknis yang nyata:
1. **Privacy vs Detection Tradeoff**: Makin detail fingerprint, makin invasif.
   Harus ada dokumentasi jelas apa yang disimpan.
2. **False Positive pada VPN/Proxy**: User dengan VPN akan sering trigger SessionFingerprint
   dan DeviceEnrollment. Perlu mekanisme trusted device enrollment yang jelas.
3. **Mobile App vs Browser**: User-Agent dan header mobile app sangat berbeda.
   Rule consistency harus punya whitelist format untuk native apps.
4. **Performance**: ResponseSizeMonitor dan SessionScanner menambah overhead di setiap
   request terautentikasi. Harus ada fast-path untuk static asset dan API ringan.
5. **Session ID Hashing**: Kita tidak boleh simpan raw session ID di database.
   Selalu gunakan sha256(session_id) sebagai kunci.

---

## 10. Ringkasan Eksekutif (TL;DR untuk Lead Dev)

```text
Sistem sekarang: Penjaga gerbang yang sangat baik (server boundary).
Celah utama: Buta total setelah user masuk (post-authentication blind spot).

Prioritas implementasi:
  1. HttpHeaderConsistencyRule   -- deteksi bot yang menyamar, mudah
  2. BehavioralVelocityRule      -- deteksi scraping post-login
  3. DeviceEnrollmentRule        -- deteksi perangkat baru/tidak dikenal
  4. SessionFingerprintRule      -- deteksi session hijacking (kritis!)
  5. DataExfiltrationRule        -- deteksi pencurian data via API
  6. Adaptive Response System    -- graduated response tanpa merusak UX

Filosofi baru yang diusulkan:
  "Authentication adalah penjaga pintu.
   Security Defense adalah kamera pengawas dan perisai.
   Session Intelligence adalah detektif yang mengikuti tamu di dalam gedung."

Total aturan setelah ekspansi: 8 + 7 = 15 aturan modular
Middleware baru: 2 (AuthenticatedSessionScanner, ResponseSizeMonitor)
Tabel baru: 2 (security_device_profiles, security_session_risks)
Event baru: 1 (SecuritySessionCompromised)
```
