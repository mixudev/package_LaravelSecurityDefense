# 08 — Troubleshooting (FAQ)

Penyelesaian masalah umum saat mengintegrasikan / memakai package.

---

## 1. Toggle Dark/Light Mode Tidak Mengubah Gaya

**Gejala:** Klik ikon tema, ikon berubah, tapi warna halaman tidak berubah.

**Penyebab:** Tailwind v4 browser runtime default memakai `prefers-color-scheme`
(media query OS), bukan class `.dark`. Toggle membolak-balik class `.dark` di
`<html>` tetapi Tailwind tidak me-map-nya.

**Solusi:** Pastikan di `resources/views/vendor/security-defense/layouts/app.blade.php`
(atau view package asli) ada blok ini:

```html
<style type="text/tailwindcss">
    @custom-variant dark (&:where(.dark, .dark *));
</style>
```

Jika blok ini hilang (mis. karena publish views lalu dihapus), tambahkan kembali.
Tidak perlu Alpine.js — toggle memakai vanilla JS bawaan layout.

---

## 2. Dashboard 403 Forbidden

**Penyebab:** Middleware `EnsureLocalAccess` menolak akses karena:
- environment bukan `local`, dan
- IP tidak ada di `allowed_ips`, dan
- Gate `viewSecurityDefenseDashboard` belum / mengembalikan false.

**Solusi:**
- Akses via `localhost`/`127.0.0.1` di environment local, atau
- tambah IP Anda ke `security-defense.dashboard.allowed_ips`, atau
- definisikan Gate `viewSecurityDefenseDashboard` untuk akses production.

Lihat [04-dashboard.md](./04-dashboard.md).

---

## 3. Dashboard 404 Not Found

**Penyebab:** `SECURITY_DEFENSE_DASHBOARD_ENABLED=false` atau route belum terdaftar.

**Solusi:** Pastikan enabled, dan cek `php artisan route:list | grep security-defense`.
Provider hanya me-load route jika `dashboard.enabled=true`.

---

## 4. Test Channel Gagal "Failed"/"Configured NO"

**Gejala:** Channel `enabled=YES` tapi `configured=NO` atau `delivery=FAILED`.

**Solusi:**
- Periksa credential di `.env` (token, webhook URL, chat id) sudah benar.
- Pastikan `SECURITY_*_ENABLED=true` setel.
- Untuk email: pastikan `MAIL_*` valid + `SECURITY_MAIL_ENABLED=true`.
- Cek log Laravel (`storage/logs/laravel.log`) untuk pesan error HTTP.
- Jaringan keluar server harus bisa akses API target (Telegram/Discord/mail).

Jalankan `php artisan security:test-webhook --all` untuk detail per channel.

---

## 5. Alert Tidak Tersimpan / Tidak Terkirim

**Penyebab umum:**
- `SECURITY_DEFENSE_ENABLED=false` (master off).
- Tabel `security_alerts` belum ada (`php artisan migrate`).
- Rate limit alert tercapai (`max_alerts_per_minute`, default 60).
- Dedup aktif menekan alert identik dalam jendela `window` (300 detik).
- Queue diaktifkan tapi worker tidak jalan.

**Cek urutan:**
1. `php artisan migrate` sudah?
2. `php artisan security:test-webhook database`.
3. Jika queue: `php artisan queue:work --queue=security-alerts`.

---

## 6. Quarantine Spontan Hilang Setelah Restart

**Penyebab:** Quarantine berbasis cache (driver file/array) hilang saat restart.

**Solusi:** Aktifkan `SECURITY_QUARANTINE_PERSIST_DB=true` dan gunakan cache
Redis/Memcached. Lihat [06-security-hardening.md](./06-security-hardening.md).

---

## 7. Deteksi "Tidak Ada" Meski Ada Serangan

**Cek:**
- Apakah telemetry benar-benar dikirim? Log event di
  `AppServiceProvider` (Failed/Login/Lockout) harus terpasang.
- Threshold rule belum tercapai? Mis. brute force butuh 10 gagal dalam 60 detik.
- Cache driver file/array mereset counter? Pakai Redis.
- `SEFURITY_DEFENSE_ENABLED` (typo) — pastikan ejaan benar.

---

## 8. False-Positive Blokir Payload (Trafik Sah Tertolak)

**Solusi:** Set `middleware.payload_scanner.action => 'log_only'` sementara,
observasi log, tambahkan nilai ke `excluded_paths` bila perlu, lalu kembali ke
`block`. Lihat [06-security-hardening.md](./06-security-hardening.md).

---

## 9. Perlu Menonaktifkan Package Penuh

```env
SECURITY_DEFENSE_ENABLED=false
```

Ini mematikan detection + alerting + WAF middleware. Dashboard & routing tetap
terdaftar bila `dashboard.enabled=true`; matikan juga dengan
`SECURITY_DEFENSE_DASHBOARD_ENABLED=false` bila perlu.

---

## 10. Emoji / Ikon Tidak Sesuai Branding

Dashboard memakai **SVG inline** (bukan emoji). Untuk ganti ikon/logo, publish
views (`security-defense-views`) dan edit `components/navbar.blade.php` /
komponen lain sesuai kebutuhan.

---

Kembali ke [README.md](./README.md) untuk daftar modul.
