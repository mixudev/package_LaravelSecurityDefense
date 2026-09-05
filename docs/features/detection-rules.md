# Aturan Deteksi Ancaman (Detection Rules)

Package ini menyediakan 11 aturan deteksi modular yang beroperasi tanpa menyimpan state di database (*stateless sliding window* melalui cache).

---

## 1. Brute Force (`BruteForceRule`)

- **Tujuan**: Mendeteksi percobaan login gagal berulang kali terhadap satu akun atau identifier yang sama.
- **Event Pemicu**: `LoginFailed`, `OTP_FAILED`.
- **Ambang Default**: 10 percobaan gagal dalam jendela 60 detik.
- **Tingkat Keparahan**: `high`.
- **Mitigasi Balapan**: Menggunakan atomic cache increment untuk mencegah lolosnya request concurrent berkecepatan tinggi.

---

## 2. Credential Stuffing (`CredentialStuffingRule`)

- **Tujuan**: Mendeteksi penyerang yang mencoba berbagai kombinasi akun berbeda dari satu alamat IP yang sama.
- **Event Pemicu**: `LoginFailed` dengan identifier berbeda dari IP identik.
- **Ambang Default**: 8 akun unik dalam 120 detik.
- **Tingkat Keparahan**: `critical`.
- **Privasi Data**: Identifier akun yang diuji disimpan dalam bentuk hash SHA-256 (`sample_identifiers_hashed`) untuk mencegah kebocoran kredensial sensitif pada log alert.

---

## 3. Distributed Password Spray (`DistributedSprayRule`)

- **Tujuan**: Mendeteksi serangan password spray terdistribusi di mana satu akun target diserang secara simultan dari banyak IP yang berbeda.
- **Event Pemicu**: `LoginFailed` pada identifier yang sama dari IP-IP berbeda.
- **Ambang Default**: 5 IP unik dalam 300 detik.
- **Tingkat Keparahan**: `high`.
- **Privasi Data**: Alamat IP penyerang di-hash dengan SHA-256 (`sample_ips_hashed`).

---

## 4. Rate Limit Bypass (`RateLimitBypassRule`)

- **Tujuan**: Mendeteksi indikasi pemalsuan identitas proxy atau rotasi header `X-Forwarded-For` secara cepat untuk mengelabui limit standar aplikasi.
- **Ambang Default**: 15 kali perubahan identitas dalam 60 detik.
- **Tingkat Keparahan**: `medium`.

---

## 5. Payload Injection (`PayloadInjectionRule`)

- **Tujuan**: Memeriksa query string URL, request body JSON/Form, dan header terhadap pola eksploitasi web berbahaya.
- **Vektor yang Didukung**:
  - **SQL Injection (SQLi)**: `UNION SELECT`, `' OR 1=1`, `information_schema`, fungsi sleep/benchmark.
  - **Cross-Site Scripting (XSS)**: Tag `<script>`, skema `javascript:`, event handler `onerror=`, `onload=`, pencurian cookie.
  - **Path Traversal / LFI**: `../`, `..\`, `/etc/passwd`, `/etc/shadow`, `win.ini`.
  - **Command Injection (RCE)**: Karakter shell separator `; whoami`, `| id`, `$(cat /etc/passwd)`.
- **Ambang Default**: Deteksi instan (1 kali percobaan langsung memicu).
- **Tingkat Keparahan**: `critical`.
- **Perlindungan ReDoS**: Panjang string dibatasi sebelum diinspeksi regex. Karakter kontrol binary otomatis dibersihkan dari sampel log.

---

## 6. Impossible Travel (`ImpossibleTravelRule`)

- **Tujuan**: Mendeteksi login berurutan yang sukses dari dua lokasi geografis yang secara fisik mustahil dicapai dalam selisih waktu tersebut.
- **Event Pemicu**: `LoginSucceeded`, `NewDeviceLoginDetected`.
- **Metode Hitung**: Rumus jarak Haversine bola bumi dibandingkan dengan selisih waktu.
- **Ambang Default**: Kecepatan fisik > 900 km/jam.
- **Tingkat Keparahan**: `high`.

---

## 7. Path Reconnaissance (`PathReconnaissanceRule`)

- **Tujuan**: Mendeteksi pemindaian otomatis terhadap file konfigurasi sensitif dan direktori admin.
- **Target Pola**: File `.env`, folder `.git/config`, `wp-config.php`, `actuator/heapdump`, `phpinfo.php`, file `.sql`, serta file cadangan database.
- **Ambang Default**: 5 probe dalam 120 detik.
- **Tingkat Keparahan**: `high`.

---

## 8. User-Agent Anomaly (`UserAgentAnomalyRule`)

- **Tujuan**: Mengidentifikasi tool scanning otomatis dan bot penyerang populer.
- **Daftar Signature**: `sqlmap`, `nikto`, `dirbuster`, `gobuster`, `wpscan`, `masscan`, `nmap`, `ffuf`, `dirsearch`, `zmap`, `cadaver`, `wfuzz`, `testssl`, `whatweb`, `sublist3r`, `katana`, `jaeles`, `dalfox`, `xsstrike`, `commix`, `tplmap`, `arachni`, `wapiti`.
- **Tingkat Keparahan**: `high`.

---

## 9. Session Fingerprint & Hijack (`SessionFingerprintRule`)

- **Tujuan**: Mendeteksi sesi yang dibajak akibat pencurian cookie oleh malware (infostealer) pada device korban.
- **Mekanisme**: Membandingkan IP subnet (/24) dan hash User-Agent dengan baseline awal saat sesi dibuat. Jika replayed dari subnet atau User-Agent yang berbeda drastis, mentrigger alert kritis.
- **Tingkat Keparahan**: `critical` / `high`.

---

## 10. Behavioral Velocity (`BehavioralVelocityRule`)

- **Tujuan**: Mendeteksi scraping bot atau otomasi abnormal pasca-login yang mengeksploitasi hak akses akun terautentikasi.
- **Ambang Default**: > 120 request per menit per user ID.
- **Tingkat Keparahan**: `high`.

---

## 11. HTTP Header Consistency (`HttpHeaderConsistencyRule`)

- **Tujuan**: Mendeteksi bot dan headless browser yang memalsukan User-Agent browser asli namun memiliki kontradiksi header (misal tanpa `Accept-Language`, atau tanpa `Sec-Fetch-*`).
- **Tingkat Keparahan**: `medium`.

