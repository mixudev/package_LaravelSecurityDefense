# Troubleshooting & FAQ

Penyelesaian masalah umum saat mengintegrasikan atau menjalankan package.

---

## 1. Dashboard Mengembalikan Respon HTTP 403 Forbidden

**Penyebab**: Middleware `EnsureLocalAccess` menolak akses pada dashboard. Kondisi lingkungan bukan `local`, atau IP klien tidak terdaftar di `allowed_ips`, atau Gate kustom `viewSecurityDefenseDashboard` belum dikonfigurasi.

**Solusi**:
- Saat development: akses melalui `localhost` atau `127.0.0.1`.
- Pada server staging/production: definisikan Laravel Gate di `AppServiceProvider::boot()`:
  ```php
  Gate::define('viewSecurityDefenseDashboard', function ($user) {
      return $user && $user->is_admin;
  });
  ```

---

## 2. Toggle Dark/Light Mode Dashboard Tidak Mengubah Gaya

**Penyebab**: Tailwind CSS versi 4 secara default memetakan variant `dark:` ke preferensi sistem operasi (`prefers-color-scheme`) alih-alih class `.dark`.

**Solusi**: Pastikan blok style berikut tetap ada di `resources/views/vendor/security-defense/layouts/app.blade.php`:

```html
<style type="text/tailwindcss">
    @custom-variant dark (&:where(.dark, .dark *));
</style>
```

---

## 3. Tidak Menerima Notifikasi Telegram / Discord

Periksa langkah-langkah berikut secara berurutan:
1. Pastikan nilai `enabled` pada bagian channel (`telegram` atau `discord`) di `config/security-defense.php` bernilai `true`.
2. Pastikan kredensial `SECURITY_TELEGRAM_BOT_TOKEN`, `SECURITY_TELEGRAM_CHAT_ID`, atau `SECURITY_DISCORD_WEBHOOK` terisi valid di `.env`.
3. Jika mode queue aktif, pastikan worker antrean berjalan:
   ```bash
   php artisan queue:work --queue=security-alerts
   ```
4. Uji konektivitas channel secara langsung:
   ```bash
   php artisan security:test-webhook telegram
   php artisan security:test-webhook discord
   ```

---

## 4. IP Penyerang Masih Bisa Mengakses Website Setelah Diblokir

**Penyebab**: Cache aplikasi di-flush (atau driver cache tidak persisten) sehingga state karantina hilang.

**Solusi**:
1. Gunakan driver cache terdistribusi Redis (`CACHE_STORE=redis`) untuk produksi.
2. Aktifkan opsi `quarantine.persist_to_database => true` pada file konfigurasi agar status karantina tetap tersimpan di database.
3. Jalankan kembali migrasi (`php artisan migrate`).

---

## 5. Tidak Muncul Alert Baru Saat Diuji Berulang

**Penyebab**: Sistem deduplikasi aktif. `AlertDeduplicator` menghitung fingerprint SHA-256 yang identik untuk serangan berulang pada target yang sama dan menekannya dalam jendela window (default 300 detik).

**Solusi**: Jika sedang mengetes berulang kali, kecilkan nilai `deduplication.window` pada file konfigurasi atau ganti identifier target/alamat IP pengujian.