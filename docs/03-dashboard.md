# 03. Portal & Dashboard Opaque

Fitur **Opaque Dashboard** dirancang untuk menyembunyikan rute dashboard keamanan dari pemindaian otomatis penyerang (discovery barrier) tanpa merusak sesi atau data terenkripsi milik aplikasi klien.

---

## 1. Alur Kerja Akses (Gate & Capability)

Tidak ada lagi URL dashboard statis yang mudah ditebak seperti `/admin/security` atau `/security-defense/dashboard`.

```text
[Operator Browser]
       │
       ▼
 1. GET /security-defense (Portal Gate)
    ├─ Diperiksa oleh EnsureLocalAccess (hanya IP terpercaya)
    └─ Ditampilkan tombol CSRF: "Enter Dashboard"
       │
       ▼
 2. POST /security-defense/enter
    ├─ Divalidasi token CSRF + IP
    ├─ Diterbitkan token capability acak:
    │  - Enkripsi AES-256-CBC
    │  - Signature HMAC-SHA256
    │  - One-time nonce acak disimpan di cache (TTL 60 detik)
    │  - Terikat pada session ID pemohon saat itu
    └─ HTTP 302 Redirect ke: /<token-capability-terenkripsi>
       │
       ▼
 3. GET /<token-capability-terenkripsi>
    ├─ Middleware ValidateOpaqueDashboardPath memvalidasi signature HMAC
    ├─ Mendekripsi payload & memeriksa masa kedaluwarsa (TTL)
    ├─ Memastikan session ID cocok dengan pemohon awal
    ├─ Menghapus nonce dari cache secara atomik (langsung hangus, anti-replay)
    ├─ Memberi hak akses dashboard pada session
    └─ Redirect internal ke: /<session-path-64-karakter>
       │
       ▼
 4. GET /<session-path>/<alias-acak>
    └─ Mengakses antarmuka dashboard dengan subrute tersamar
```

---

## 2. Isolasi Kunci: Keamanan Database Klien

Banyak aplikasi Laravel menggunakan enkripsi kolom database bawaan:
```php
protected $casts = [
    'nik' => 'encrypted',
    'credit_card' => 'encrypted',
];
```
Jika kunci enkripsi dashboard bercampur langsung dengan `APP_KEY` utama, merotasi kunci karena insiden dashboard akan **merusak seluruh data terenkripsi di database klien** dan mengeluarkan semua user aktif (`DecryptException`).

### Mekanisme Perlindungan Kami:
1. **Derivasi HKDF Otomatis (Bawaan)**:
   Package tidak pernah menggunakan `APP_KEY` secara mentah. Kunci enkripsi dan HMAC diturunkan menggunakan standar kriptografi **HKDF (Hash-based Key Derivation Function)** dengan info konteks unik:
   - `security-defense:dashboard:encryption:v1`
   - `security-defense:dashboard:hmac:v1`
2. **Kunci Mandiri Opsional (`SECURITY_DEFENSE_KEY`)**:
   Untuk isolasi fisik 100%, Anda dapat mendefinisikan kunci terpisah di file `.env`:
   ```env
   SECURITY_DEFENSE_KEY=base64:random32byteskeyhere...
   ```
   Jika kunci ini dirotasi, **hanya URL dashboard lama yang kedaluwarsa**. Seluruh data database klien, session cookie, dan signed URL Laravel **sama sekali tidak terpengaruh dan tetap aman**.

---

## 3. Anti-Replay & Kedaluwarsa Otomatis

- **Satu Kali Pakai (One-Time Only)**: URL token hanya berlaku tepat 1 kali. Begitu token diklik dan berhasil membuka dashboard, noncenya langsung dihapus dari cache server. Membuka ulang link dari riwayat peramban atau tab lain akan menghasilkan `404 Not Found`.
- **Batas Waktu Cepat (TTL)**: Token memiliki masa kedaluwarsa bawaan selama 60 detik (`dashboard.opaque_path.ttl_seconds`). Jika tidak diklik dalam 60 detik, token hangus otomatis.
- **Terikat Sesi (Session-Bound)**: Token yang dibuat di sesi peramban A tidak dapat dibuka di peramban B meskipun URL disalin secara utuh.

---

## 4. Penyamaran Rute Internal (Opaque Aliases)

Setelah masuk melalui gate, subrute fungsional dashboard tidak menggunakan kata kunci standar:

| Nama Halaman | Rute Standar | Rute Opaque Tersamar |
|---|---|---|
| Dashboard Utama | `/security-defense` | `/<session_path>` |
| Log Audit Data | `/security-defense/data-audits` | `/<session_path>/m4q8` |
| Sesi & Intelijen | `/security-defense/sessions` | `/<session_path>/r9v3` |
| Analisis Epistemik | `/security-defense/epistemic` | `/<session_path>/t6x1` |
| Event Real-time | `/security-defense/live-events` | `/<session_path>/l2h7` |
| Aksi Karantina IP | `/security-defense/quarantine/*` | `/<session_path>/q5b2/*` |

Penyerang atau alat pemindai tidak akan dapat menyimpulkan fungsi halaman dari URL yang dikunjungi.

---

## 5. Simulasi Akses Publik Tanpa Hosting (via Secure Tunnel)

Anda dapat menguji apakah gate dan rute opaque berfungsi dari internet publik tanpa perlu membeli VPS/hosting, menggunakan tunnel gratis seperti **ngrok** atau **Cloudflare Tunnel (`cloudflared`)**.

> **Peringatan Keamanan:** Jangan pernah melakukan Port Forwarding router langsung ke laptop/PC Anda untuk simulasi publik. Menggunakan tunnel jauh lebih aman karena lalu lintas dienkripsi melalui TLS edge dan IP publik rumah Anda terlindungi.

### Langkah 1: Pengaturan Environment `.env`
Buka file `.env` aplikasi Anda dan sesuaikan switch dashboard:

```env
# Matikan mode strictly local agar cabang public dievaluasi
SECURITY_DEFENSE_DASHBOARD_LOCAL_ONLY=false

# Aktifkan akses publik terkontrol
SECURITY_DEFENSE_DASHBOARD_PUBLIC_ENABLED=true

# Masukkan IP publik Anda (cek di https://api.ipify.org)
# Pisahkan dengan koma jika ada lebih dari 1 IP yang diizinkan
SECURITY_DEFENSE_DASHBOARD_PUBLIC_IPS=36.68.52.210
```

### Langkah 2: Daftarkan Trusted Proxies (Laravel 11+)
Agar Laravel dapat membaca IP asli klien dari header `X-Forwarded-For` yang dikirim oleh tunnel, tambahkan konfigurasi loopback proxy pada `bootstrap/app.php`:

```php
->withMiddleware(function (Middleware $middleware): void {
    // Mempercayai header proxy HANYA dari loopback (tunnel lokal forward ke 127.0.0.1)
    $middleware->trustProxies(at: ['127.0.0.1', '::1']);
})
```

### Langkah 3: Jalankan Tunnel
Jalankan salah satu perkakas tunnel berikut:

**Opsi A: Menggunakan ngrok**
```bash
ngrok http 8000
```
Salin URL publik HTTPS yang diberikan oleh ngrok (misal `https://a1b2-c3d4.ngrok-free.app`).

**Opsi B: Menggunakan Cloudflare Tunnel (Tanpa Akun)**
```bash
cloudflared tunnel --url http://127.0.0.1:8000
```
Salin URL publik trycloudflare (misal `https://random-name.trycloudflare.com`).

### Langkah 4: Pengujian Skenario Keamanan
1. **Skenario 1 - IP Diizinkan (Operator Sah)**:
   - Akses URL tunnel dari browser Anda: `https://<tunnel-url>/security-defense`
   - Jika Anda sudah login (`require_authenticated_user = true`) dan IP Anda terdaftar di `allowed_ips`, halaman gate terbuka dengan status **200 OK**.
   - Klik tombol **"Enter Dashboard"** untuk masuk ke dashboard capability.
2. **Skenario 2 - IP Asing / Penyerang**:
   - Coba buka URL gate menggunakan koneksi internet lain (misal tethering seluler berbeda yang IP-nya tidak didaftarkan).
   - Hasil: Langsung ditolak dengan status **`403 Forbidden`** (fail-closed) dan denial dicatat ke log telemetri dengan rate limiting.

