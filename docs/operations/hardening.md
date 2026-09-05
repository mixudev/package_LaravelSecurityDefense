# Hardening & Optimasi Produksi

Rekomendasi konfigurasi untuk menggelar `mixudev/security-defense` pada lingkungan dengan lalu lintas data tinggi (*high traffic*).

---

## 1. Wajib: Gunakan Cache Terdistribusi (Redis / Memcached)

Package mengandalkan sliding window, deduplikasi alert, dan sistem karantina berbasis memory cache.

**Hindari penggunaan driver cache `file` atau `array` pada produksi**:
- Driver file/array akan kehilangan seluruh counter frekuensi dan daftar karantina setiap kali proses web server restart atau dideploy.
- Pada arsitektur multi-server / load balancer, Redis memastikan state karantina IP dan skor risiko berlaku terpusat di seluruh node aplikasi.

Di file `.env` aplikasi:
```env
CACHE_STORE=redis
```

---

## 2. Aktifkan Durabilitas Karantina Database

Agar IP penyerang tetap terisolasi bahkan ketika Redis di-flush atau restart maintenance, aktifkan opsi database persistence pada `config/security-defense.php`:

```php
'middleware' => [
    'quarantine' => [
        'persist_to_database' => true,
    ],
],
```

Pastikan migrasi tabel `security_quarantines` sudah dijalankan (`php artisan migrate`).

---

## 3. Optimasi Fast-Path untuk Trafik Tinggi

Untuk menghemat CPU server saat melayani jutaan request GET/HEAD bersih, pastikan opsi fast-path aktif:

```php
'middleware' => [
    'payload_scanner' => [
        'scan_empty_requests' => false, // Lewati regex scan pada GET/HEAD tanpa body & query
    ],
],
```

---

## 4. Parameter Self-Defense Bawaan

Package telah dilengkapi pengaman bawaan agar tidak menjadi korban eksploitasi DoS:

| Fitur Pengaman | Kunci Konfigurasi | Manfaat |
|---|---|---|
| Anti-ReDoS | `hardening.max_inspection_length` (4096) | Mencegah CPU hang akibat evaluasi regex pada string raksasa |
| Anti-OOM | `hardening.max_traversal_depth` (5) | Mencegah stack overflow pada struktur array bertingkat |
| Anti-Disk Flood | `hardening.alert_rate_limit` (60/menit) | Mencegah penyerang memenuhi kapasitas disk database dengan jutaan record alert |
| Memory Bounding | `detection.scoring.max_records` (50) | Membatasi jumlah riwayat histori per entitas di memori cache |
