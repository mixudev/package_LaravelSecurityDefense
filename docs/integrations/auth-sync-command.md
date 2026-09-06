# Command `auth:sync` (Bridge Event otomatis dengan Package Autentikasi)

Perintah Artisan untuk membuat file bridge (`Event Subscriber`) yang menghubungkan `mixudev/security-defense` dengan `mixudev/laravel-authentication`: satu file yang mendengarkan seluruh event domain autentikasi dan meneruskannya ke mesin SIEM/deteksi via `SecurityDefense::record()`.

`auth:sync` **hanya** membuat file yang dibutuhkan sisi defense. Instalasi package auth (composer require, publish config, migrasi) sepenuhnya urusan package auth itu sendiri — jalankan `php artisan authentication:install` di sana.

---

## 1. Daftar Kebutuhan (Requirements Checklist)

- [ ] **PHP 8.2+** dan **Laravel 11.x, 12.x, atau 13.x**.
- [ ] **`mixudev/security-defense`** sudah terpasang dan service provider terdaftar (auto-discovery).
- [ ] **`mixudev/laravel-authentication`** sudah terpasang: `composer require mixudev/laravel-authentication` lalu `php artisan authentication:install`.
- [ ] **Okses tulis** ke `app/Listeners/`.

---

## 2. Cara Menggunakan

```bash
# Buat bridge subscriber
php artisan auth:sync

# Tampilkan langkah tanpa menulis apa pun
php artisan auth:sync --dry-run

# Timpa bridge subscriber yang sudah ada
php artisan auth:sync --force
```

### Alur yang dijalankan

| # | Langkah | Keterangan |
|---|---|---|
| 1 | Deteksi package auth | `class_exists(Vendor\LaravelAuthentication\Providers\AuthenticationServiceProvider::class)` |
| 2 | Buat bridge subscriber | Tulis `app/Listeners/AuthenticationSecuritySubscriber.php` (12 handler event) |
| 3 | Inject WAF middleware | Tambahkan `RequestThreatScanner` (komponen package defense sendiri) ke `bootstrap/app.php` (L11+) atau `app/Http/Kernel.php` (L10) jika belum terdaftar |
| 4 | Registrasi subscriber | Cetak kode `Event::subscribe(...)` yang perlu ditambahkan di `AppServiceProvider::boot()` |

Command **tidak** menginstal package auth (`composer require mixudev/laravel-authentication` → lakukan via `authentication:install`), **tidak** mem-publish config/migrasi package auth, dan **tidak** mengubah `AppServiceProvider` — baris `Event::subscribe()` dicetak sebagai instruksi agar developer memilih sendiri lokasi registrasi.

---

## 3. Bridge Subscriber yang Dihasilkan

File `app/Listeners/AuthenticationSecuritySubscriber.php` berisi satu handler per event package autentikasi, masing-masing memanggil `SecurityDefense::record()`:

| Event `mixudev/laravel-authentication` | `eventType` | Metadata tambahan |
|---|---|---|
| `LoginFailed` | `LoginFailed` | `reason`, `user_id` |
| `LoginSucceeded` | `LoginSucceeded` | `strategy`, `user_id` |
| `AccountLocked` | `AccountLocked` | `lockout_duration_minutes`, `user_id` |
| `NewDeviceLoginDetected` | `NewDeviceLoginDetected` | `device_id`, `user_id` |
| `OtpVerified` | `OTP_VERIFIED` | `user_id` |
| `PasswordChanged` | `PasswordChanged` | `user_id` |
| `SessionRevoked` | `SessionRevoked` | `session_id`, `user_id` |
| `LogoutPerformed` | `LogoutPerformed` | `user_id` |
| `UserRegistered` | `UserRegistered` | `user_id` |
| `PasswordResetRequested` | `PasswordResetRequested` | `user_id` |
| `PasswordResetCompleted` | `PasswordResetCompleted` | `user_id` |
| `EmailVerified` | `EmailVerified` | `user_id` |

Semua handler memakai `context->ipAddress` dan `context->userAgent` dari `AuthenticationContext` sehingga telemetri tetap konsisten dengan alamat IP asli klien (bukan IP server).

---

## 4. Registrasi Subscriber (Manual Satu Baris)

Setelah `auth:sync` selesai, daftarkan subscriber di `AppServiceProvider::boot()`:

```php
use Illuminate\Support\Facades\Event;

public function boot(): void
{
    Event::subscribe(\App\Listeners\AuthenticationSecuritySubscriber::class);
}
```

Tanpa registrasi ini, file subscriber dibuat tetapi event tidak pernah diteruskan ke `SecurityDefense::record()`.

---

## 5. Yang TIDAK Dilakukan Command (Aman & Tidak Destruktif)

- `auth:sync` **tidak** menjalankan `composer require mixudev/laravel-authentication` — instalasi package auth dilakukan via command package auth itu sendiri (`authentication:install`).
- **tidak** mem-publish config/migrasi package auth (`config/authentication.php`, `database/migrations/`).
- **tidak** menjalankan `php artisan migrate`.
- **tidak** menimpa file yang sudah ada kecuali diberi `--force`.

---

## 6. Pemecahan Masalah

| Gejala | Penyebab | Solusi |
|---|---|---|
| `mixudev/laravel-authentication belum terpasang` | Package auth belum di-install | `composer require mixudev/laravel-authentication` lalu `php artisan authentication:install`, ulangi `php artisan auth:sync` |
| Subscriber tidak berfungsi | Belum ada `Event::subscribe()` di provider | Tambahkan baris registrasi (lihat bagian 4) |
| Perlu regenerasi bridge | Mapping event berubah | `php artisan auth:sync --force` |

---

## 7. Verifikasi End-to-End

1. `php artisan auth:sync` — pastikan output menunjukkan bridge dibuat.
2. Cek file: `app/Listeners/AuthenticationSecuritySubscriber.php` ada.
3. Registrasi subscriber di `AppServiceProvider::boot()`.
4. Login sekali (gagal lalu sukses), lalu cek dashboard SIEM `security-defense` — event `LoginFailed`/`LoginSucceeded` tercatat.