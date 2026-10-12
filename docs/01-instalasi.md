# 01. Panduan Instalasi

Dokumentasi ini menjelaskan langkah instalasi package **mixudev/security-defense** di aplikasi Laravel Anda.

---

## 1. Persyaratan Sistem

- PHP: `^8.2` (termasuk PHP 8.3, 8.4, dan 8.5)
- Laravel: `^10.0`, `^11.0`, atau `^12.0`
- Cache Driver yang mendukung atomic lock & TTL (disarankan `redis`, `database`, atau `file`)
- Kunci aplikasi (`APP_KEY`) terpasang di file `.env`

---

## 2. Pemasangan Package via Composer

Jalankan perintah berikut di root project Laravel Anda:

```bash
composer require mixudev/security-defense
```

---

## 3. Instalasi Cepat Satu Perintah

Cukup satu perintah tunggal tanpa flag tambahan untuk menginstal dan mengaktifkan seluruh benteng keamanan:

```bash
php artisan security-defense:install
```
Atau via alias praktis:
```bash
php artisan security:install
```

Perintah di atas secara otomatis dan profesional akan:
- Mempublish file konfigurasi (`config/security-defense.php`)
- Menjalankan migrasi database keamanan
- Mengaktifkan fitur dashboard opaque capability-gated
- Menginjeksi middleware WAF (`RequestThreatScanner`) & CSP (`AddContentSecurityPolicy`) ke `bootstrap/app.php`
- Me-refresh dan mengoptimalkan konfigurasi serta route cache

> **Catatan View:** Perintah instalasi ini secara sengaja **TIDAK** mempublish file template Blade dashboard ke project Anda agar kode view tetap bersih dan selalu mengikuti update terbaru dari package. Jika Anda perlu mengkustomisasi tampilan UI dashboard, lakukan publish manual (lihat bagian 5).

---

## 4. Opsi Kustomisasi (Jika Diperlukan)

Jika Anda ingin menyesuaikan instalasi secara granular, gunakan flag `--`:

| Opsi | Fungsi |
|---|---|
| `--without-csp` / `--no-csp` | Melewati injeksi middleware Content-Security-Policy ke `bootstrap/app.php` |
| `--without-scanner` / `--no-scanner` | Melewati injeksi middleware WAF `RequestThreatScanner` |
| `--without-opaque-path` / `--no-opaque-path` | Tidak mengaktifkan portal dashboard opaque |
| `--without-migrations` / `--no-migrate` | Melewati proses migrasi database |
| `--without-cache` / `--no-cache` | Melewati pembersihan dan pembuatan ulang route/config cache |
| `--force` | Menimpa file konfigurasi yang sudah ada |
| `--dry-run` | Menampilkan simulasi langkah yang akan dijalankan tanpa mengubah file apa pun |

---

## 5. Penerbitan Views (Opsional)

Jika Anda ingin mengubah tampilan antarmuka (UI) dashboard internal:

```bash
php artisan vendor:publish --tag=security-defense-views
```

File Blade akan disalin ke direktori `resources/views/vendor/security-defense/`.

---

## 6. Langkah Lanjutan

- Jika Anda menggunakan package otentikasi **mixudev/laravel-authentication**, lanjutkan ke [04. Integrasi Laravel Authentication](./04-integrasi-auth.md) untuk menghubungkan event keamanan secara otomatis.
- Pelajari arsitektur URL bertopeng dan cara kerja gate di [03. Portal & Dashboard Opaque](./03-dashboard.md).
