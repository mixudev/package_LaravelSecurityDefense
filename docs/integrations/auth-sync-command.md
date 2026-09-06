# Command `auth:sync` (Sinkronisasi Otomatis dengan Package Autentikasi)

Perintah Artisan untuk mengintegrasikan `mixudev/security-defense` dengan `mixudev/laravel-authentication` secara otomatis: menginstal package auth, mem-publish aset, menyuntikkan middleware WAF, dan membuat `Event Subscriber` bridge yang mengalirkan seluruh event domain autentikasi ke mesin SIEM/deteksi.

---

## 1. Daftar Kebutuhan (Requirements Checklist)

- [ ] **PHP 8.2+** dan **Laravel 11.x, 12.x, atau 13.x**.
- [ ] **`mixudev/security-defense`** sudah terpasang dan service provider terdaftar (auto-discovery).
- [ ] **Composer** dapat dijalankan dari terminal (untuk penginstalan package auth jika belum ada).
- [ ] **Okses tulis** ke `config/`, `database/migrations/`, `app/Listeners/`, dan `bootstrap/app.php` (atau `app/Http/Kernel.php`).

---

## 2. Cara Menggunakan

```bash
# Instalasi + sinkronisasi penuh
php artisan auth:sync

# Tampilkan langkah yang akan dilakukan tanpa menulis apa pun
php artisan auth:sync --dry-run

# Timpa file publish dan bridge yang sudah ada
php artisan auth:sync --force

# Tentukan binary composer kustom (misal composer.phar)
php artisan auth:sync --composer="php /path/composer.phar"
```

### Alur yang dijalankan

| # | Langkah | Keterangan |
|---|---|---|
| 1 | Instal package auth | `composer require mixudev/laravel-authentication` (jika belum terpasang) |
| 2 | Publish config | `vendor:publish --tag=authentication-config` → `config/authentication.php` |
| 3 | Publish migrasi | `vendor:publish --tag=authentication-migrations` → `database/migrations/` |
| 4 | Suntik middleware WAF | Tambahkan `RequestThreatScanner` ke `bootstrap/app.php` (L11+) atau `app/Http/Kernel.php` (L10) |
| 5 | Buat bridge subscriber | Tulis `app/Listeners/AuthenticationSecuritySubscriber.php` (12 handler event) |
| 6 | Registrasi subscriber | Cetak kode `Event::subscribe(...)` yang perlu ditambahkan di `AppServiceProvider::boot()` |

Command **tidak** langsung mengubah `AppServiceProvider` — baris `Event::subscribe()` dicetak sebagai instruksi agar developer memilih sendiri lokasi registrasi.

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

- `auth:sync` **tidak** menjalankan migrasi (`php artisan migrate`) — dilakukan manual setelah ditinjau, karena package auth membuat banyak tabel baru.
- **tidak** menimpa file yang sudah ada (config/migrasi/bridge) kecuali diberi `--force`.
- **tidak** menghapus atau mengubah konfigurasi `.env` dan file kredensial.
- **tidak** menimpa implementasi custom subscriber yang sudah dibuat developer (`--force` pun hanya menimpa jika diminta eksplisit).

---

## 6. Pemecahan Masalah

| Gejala | Penyebab | Solusi |
|---|---|---|
| `Composer install failed` | Paket auth gagal diunduh/di-resolve | Jalankan manual `composer require mixudev/laravel-authentication`, lalu ulangi `php artisan auth:sync` |
| Subscriber tidak berfungsi | Belum ada `Event::subscribe()` di provider | Tambahkan baris registrasi (lihat bagian 4) |
| `[WARN] bootstrap/app.php found but no $middleware->append( pattern` | File memakai notasi middleware berbeda | Daftarkan `RequestThreatScanner` secara manual di `bootstrap/app.php` |
| Perlu regenerasi bridge | Mapping event berubah | `php artisan auth:sync --force` |

---

## 7. Verifikasi End-to-End

1. `php artisan auth:sync` — pastikan output menunjukkan semua 6 langkah sukses.
2. Cek registrasi: `php artisan route:list | grep auth` — route package auth muncul.
3. Cek bridge: file `app/Listeners/AuthenticationSecuritySubscriber.php` ada.
4. Jalankan migrasi: `php artisan migrate`.
5. Login sekali (gagal lalu sukses), lalu cek dashboard SIEM `security-defense` — event `LoginFailed`/`LoginSucceeded` tercatat.