# 05. Fitur Keamanan & Mesin Deteksi

Package **mixudev/security-defense** memiliki arsitektur pertahanan berlapis untuk mendeteksi, mengkorelasikan, dan menghentikan ancaman secara otomatis sebelum mencapai lapisan kode aplikasi Anda.

---

## 1. Preventive Web Application Firewall (WAF)

Middleware `RequestThreatScanner` memindai setiap masukan pada `query`, `body`, `headers`, dan `cookies` secara non-intrusif sebelum controller aplikasi Anda dipanggil.

### Aturan Inspeksi:
1. **SQL Injection (SQLi)**: Mendeteksi pola query berbahaya seperti `' OR 1=1`, `UNION SELECT`, `SLEEP()`, manipulasi komentar SQL, dan pembacaan skema database.
2. **Cross-Site Scripting (XSS)**: Mendeteksi penyuntikan tag `<script>`, pseudo-protokol `javascript:`, payload berbasis SVG onload, serta injeksi atribut DOM berbahaya.
3. **Path & Directory Traversal**: Mendeteksi upaya membaca file sistem di luar web root (`../`, `..\`, `%2e%2e%2f`, `/etc/passwd`).
4. **Command Injection**: Mendeteksi penyuntikan karakter pipe dan eksekutor terminal shell (`| whoami`, `; cat`, `$(id)`, `` `ls` ``).
5. **User-Agent Scanner Anomaly**: Mengidentifikasi dan memblokir otomatis tanda pengenal dari perkakas penyerang otomatis seperti `sqlmap`, `nikto`, `gobuster`, `dirbuster`, dan `wpscan`.

Setiap pelanggaran langsung ditolak dengan status **`403 Forbidden`** (jika mode `block` aktif) dan dicatat ke log telemetri.

---

## 2. Behavioral Velocity & Brute Force Engine

Bukan hanya melihat request individual, mesin ini mengamati pola perilaku penyerang dari waktu ke waktu:
- **Brute Force Detection**: Mengidentifikasi rentetan kegagalan login pada satu akun spesifik.
- **Distributed Spray Detection**: Mengidentifikasi penyerang yang mencoba beberapa username berbeda secara perlahan dari satu IP atau subnet untuk menghindari threshold brute force konvensional.
- **Impossible Travel**: Menghitung kecepatan perpindahan geografis antara dua login berhasil berturut-turut. Jika user login di Jakarta lalu 5 menit kemudian login dari Frankfurt, sistem otomatis menaikkan peringatan anomali perjalanan mustahil.

---

## 3. Epistemic SIEM Analyzer

Package ini menyertakan penganalisis berbasis bukti (epistemic reasoning) yang menghitung tingkat keyakinan (confidence score) dari setiap insiden menggunakan korelasi Bayesian:
- Menggabungkan sinyal WAF + kegagalan otentikasi + anomali perangkat menjadi satu skor ancaman terpadu (0 - 100).
- Mengeliminasi false positive: aktivitas dari IP terdaftar atau user terpercaya tidak langsung diblokir secara agresif.
- Memungkinkan operator memberikan feedback (True Positive / False Positive) melalui dashboard untuk melatih bobot deteksi secara adaptif.

---

## 4. Sistem Karantina IP Otomatis

Ketika skor ancaman suatu alamat IP melewati batas ambang (default `threshold = 100`):
- Alamat IP penyerang langsung dimasukkan ke dalam daftar **Karantina Sementara**.
- Seluruh request berikutnya dari IP tersebut langsung diputus di lapisan terluar (HTTP `403 Forbidden` atau `429 Too Many Requests`).
- Durasi karantina default adalah 60 menit dan dapat disesuaikan.
- IP di dalam `quarantine.whitelisted_ips` tidak akan pernah dikarantina secara otomatis.

---

## 5. Saluran Notifikasi Alert Real-Time

Insiden kritis dapat langsung dikirim ke berbagai channel komunikasi operator:

### A. Bot Telegram Interaktif
Notifikasi dikirim langsung ke grup/channel keamanan Telegram Anda, lengkap dengan tombol interaktif:
- **Pardon IP**: Membebaskan IP yang tidak sengaja terblokir langsung dari aplikasi Telegram.
- **Whitelist IP**: Memasukkan IP ke daftar putih permanen dengan satu ketukan tombol.
- Interaksi diamankan menggunakan token webhook rahasia (`X-Telegram-Bot-Api-Secret-Token`).

### B. Webhook SIEM
Meneruskan seluruh payload insiden dalam format JSON ke endpoint SIEM perusahaan (seperti Datadog, Splunk, Elastic, atau server monitoring kustom). Payload ditandatangani menggunakan header `X-Security-Defense-Signature` berbasis HMAC-SHA256 untuk menjamin integritas data.

### C. Logging Standar
Mencatat seluruh aktivitas ke channel log Laravel (`storage/logs/laravel.log`) dengan data sensitif (password, secret token, session id) yang sudah disamarkan (redacted).
