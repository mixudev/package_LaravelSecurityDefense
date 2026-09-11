# 06. Operasi, Hardening, dan Pemecahan Masalah

Panduan praktis pemeliharaan harian, pengerasan keamanan (hardening) sebelum rilis ke production, serta solusi atas kendala yang sering ditemui.

---

## 1. Pemecahan Masalah Umum (Troubleshooting)

### A. Muncul `403 Forbidden` saat Membuka `/security-defense` di Komputer Lokal
**Penyebab:**
Middleware `EnsureLocalAccess` secara ketat memeriksa dua hal:
1. `APP_ENV` harus bernilai `local` (bukan `production` atau `testing`).
2. Alamat IP pemohon harus loopback (`127.0.0.1`, `::1`, atau `localhost`).

**Solusi:**
1. Pastikan di file `.env` aplikasi Anda:
   ```env
   APP_ENV=local
   ```
2. **Penting:** Jika Anda mengubah nilai `APP_ENV` saat server PHP sedang berjalan (`php artisan serve`), server PHP built-in **tidak otomatis membaca ulang environment**. Matikan proses server (`Ctrl+C`) lalu jalankan ulang.
3. Jika menggunakan custom domain lokal (misal `my-app.test`), pastikan `my-app.test` diarahkan ke `127.0.0.1` pada file `hosts` sistem operasi Anda.

---

### B. Muncul `404 Not Found` saat Membuka URL Capability Dashboard
**Penyebab:**
1. URL tersebut sudah pernah diklik sebelumnya (bersifat **one-time**).
2. URL sudah melewati batas waktu 60 detik sejak diterbitkan (**TTL expired**).
3. Anda membuka link tersebut di peramban atau mode incognito yang berbeda dari saat meminta di gate (**session mismatch**).

**Solusi:**
Buka kembali gate `/security-defense` dan klik tombol **"Enter Dashboard"** untuk mendapatkan URL capability baru.

---

### C. Error `server.php not found` saat Menjalankan Server
**Penyebab:**
Laravel modern (versi 11 dan 12) tidak lagi memiliki file `server.php` di root direktori aplikasi. Jika ada skrip manual yang memanggil `php -S 127.0.0.1:8000 server.php`, proses tersebut akan gagal.

**Solusi:**
Selalu gunakan perintah resmi Laravel:
```bash
php artisan serve
```
Atau jika menggunakan PHP built-in secara langsung, tentukan direktori public:
```bash
php -S 127.0.0.1:8000 -t public
```

---

### D. Muncul Halaman "Portal Akses Dibatasi" (403) saat Mengakses via IP LAN Laptop
**Penyebab:**
Alamat IP LAN laptop (misalnya `192.168.1.178`) bukan loopback (`127.0.0.1`). Middleware keamanan menolaknya karena IP belum terdaftar di whitelist atau environment diset ke `production`.

**Solusi:**
1. Tambahkan IP laptop Anda ke array `allowed_ips` di file `config/security-defense.php`:
   ```php
   'dashboard' => [
       'allowed_ips' => ['127.0.0.1', '::1', '192.168.1.178'],
   ],
   ```
2. Pastikan file `.env` bernilai `APP_ENV=local`.
3. Jalankan `php artisan config:clear && php artisan route:clear`.
4. Jika server PHP sedang berjalan, matikan lalu jalankan ulang agar memuat environment baru.

---

### E. Dashboard Tiba-tiba Menghasilkan 404 Setelah Ditinggal Beberapa Saat
**Penyebab:**
Fitur **Idle Timeout** (`dashboard.opaque_path.session_ttl_seconds`, bawaan 15 menit / 900 detik) telah kedaluwarsa demi keamanan. Fitur ini memastikan jika laptop ditinggal tanpa pengawasan, URL dashboard tidak dapat disalahgunakan oleh pihak lain.

**Solusi:**
Buka kembali portal gate (`/security-defense`) dan klik **"Enter Dashboard"** untuk menerbitkan sesi dan rute acak yang baru.

---

## 2. Checklist Hardening Sebelum Rilis Production

Sebelum meluncurkan aplikasi ke lingkungan production:

1. **Aktifkan Opaque Dashboard**:
   Pastikan opsi opaque aktif agar dashboard tersembunyi dari scanner otomatis:
   ```bash
   php artisan security-defense:install --with-opaque-path
   ```
2. **Gunakan Kunci Mandiri Opsional (`SECURITY_DEFENSE_KEY`)**:
   Tambahkan `SECURITY_DEFENSE_KEY` di `.env` production untuk mengisolasi total siklus rotasi kunci dashboard dari database klien:
   ```env
   SECURITY_DEFENSE_KEY=base64:...
   ```
3. **Konfigurasi Allowed IPs / CIDR untuk Mode Publik**:
   Jika dashboard harus dibuka dari luar jaringan kantor (non-loopback), atur allowlist IP secara eksplisit di file konfigurasi:
   ```php
   'dashboard' => [
       'local_only' => false,
       'public' => [
           'enabled' => true,
           'allowed_ips' => ['203.0.113.50'], // IP VPN atau kantor
           'allowed_cidrs' => ['198.51.100.0/24'],
           'require_authenticated_user' => true,
       ],
   ],
   ```
4. **Daftarkan Trusted Proxies (Jika di Belakang Reverse Proxy / Load Balancer)**:
   Jika server Anda menerima lalu lintas melalui Nginx, Cloudflare, atau AWS ALB, daftarkan IP proxy tersebut di `dashboard.trusted_proxies` agar header `X-Forwarded-For` diproses dengan benar dan upaya spoofing dari koneksi langsung diabaikan:
   ```php
   'dashboard' => [
       'trusted_proxies' => [
           '127.0.0.1', '::1',
           '10.0.0.1', // IP internal load balancer / Nginx
       ],
   ],
   ```
5. **Perbarui Cache Rute dan Konfigurasi**:
   Setiap kali melakukan deployment di production:
   ```bash
   php artisan config:cache
   php artisan route:cache
   ```

---

## 3. Pemeliharaan & Perintah Diagnosa Berkala

### A. Pembersihan Data Telemetri Lama (`security-defense:prune`)
Data log audit, riwayat ancaman, dan event lama perlu dibersihkan secara berkala agar ukuran database tetap terkontrol.

```bash
# Menghapus data telemetri yang lebih tua dari retensi bawaan
php artisan security-defense:prune
```

Anda dapat menjadwalkan perintah ini di scheduler Laravel (`routes/console.php`):
```php
use Illuminate\Support\Facades\Schedule;

Schedule::command('security-defense:prune')->daily();
```

### B. Uji Notifikasi Alert Webhook
Untuk memverifikasi apakah endpoint webhook SIEM Anda menerima payload dengan benar:
```bash
php artisan security:test-webhook
```

### C. Mode Polling Telegram (untuk localhost tanpa daemon)
Jika aplikasi belum bisa menerima webhook publik (misalnya saat development di `localhost`), jalankan polling:
```bash
php artisan security:telegram-poll
```
