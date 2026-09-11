# 04. Integrasi Laravel Authentication

Package **mixudev/security-defense** dirancang berdampingan secara mulus dengan **mixudev/laravel-authentication**.

Untuk mencegah duplikasi logika otentikasi, package ini tidak membuat sistem login sendiri. Sebagai gantinya, tersedia perintah satu langkah untuk menghubungkan seluruh event keamanan dari package auth ke dalam mesin deteksi intelijen ancaman.

---

## 1. Perintah Jembatan Otomatis (`auth:sync`)

Jalankan perintah ini di root project Anda:

```bash
php artisan auth:sync
```

Perintah ini akan melakukan dua hal secara otomatis:
1. **Membuat Subscriber Jembatan**: Mengenerate file `app/Listeners/AuthenticationSecuritySubscriber.php` yang memetakan seluruh event dari namespace `Vendor\LaravelAuthentication\Events\*` ke `SecurityDefense::record()`.
2. **Auto-Injeksi WAF Middleware**: Menyuntikkan middleware `RequestThreatScanner` ke dalam pipeline HTTP aplikasi Anda:
   - Di Laravel 11+: Otomatis disisipkan ke file `bootstrap/app.php`.
   - Di Laravel 10: Otomatis disisipkan ke file `app/Http/Kernel.php`.

Opsi perintah yang tersedia:
```bash
# Menimpa file subscriber yang sudah ada jika ada update mapping baru
php artisan auth:sync --force

# Melihat simulasi perubahan tanpa menulis file apa pun
php artisan auth:sync --dry-run
```

---

## 2. Pendaftaran Subscriber

Jika menggunakan Laravel 11+, daftarkan subscriber tersebut di file `app/Providers/AppServiceProvider.php`:

```php
namespace App\Providers;

use App\Listeners\AuthenticationSecuritySubscriber;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        Event::subscribe(AuthenticationSecuritySubscriber::class);
    }
}
```

---

## 3. 12 Domain Event yang Dipantau Otomatis

Subscriber jembatan secara otomatis menangkap dan menganalisis 12 event penting berikut ke dalam mesin SIEM:

| Event Asal | Event Type SIEM | Dampak Deteksi |
|---|---|---|
| `LoginFailed` | `LoginFailed` | Memicu perhitungan batas Brute Force dan pendeteksian Credential Stuffing |
| `LoginSucceeded` | `LoginSucceeded` | Menghitung kecepatan perpindahan lokasi geografis (Impossible Travel) |
| `AccountLocked` | `AccountLocked` | Menaikkan skor risiko IP dan mencatat riwayat pemblokiran akun |
| `NewDeviceLoginDetected` | `NewDeviceLoginDetected` | Anomali sidik jari perangkat baru (Browser / OS Anomaly) |
| `OtpVerified` | `OTP_VERIFIED` | Mereset kecurigaan brute force faktor kedua (2FA) |
| `PasswordChanged` | `PasswordChanged` | Mengaudit rotasi kredensial pengguna |
| `SessionRevoked` | `SessionRevoked` | Pencabutan sesi jarak jauh oleh admin atau pengguna |
| `LogoutPerformed` | `LogoutPerformed` | Mengakhiri jejak sesi di intelijen sesi |
| `UserRegistered` | `UserRegistered` | Mengawasi registrasi massal dari IP yang sama (Account Creation Spam) |
| `PasswordResetRequested` | `PasswordResetRequested` | Mendeteksi spray permintaan reset kata sandi |
| `PasswordResetCompleted` | `PasswordResetCompleted` | Verifikasi penyelesaian alur pemulihan akun |
| `EmailVerified` | `EmailVerified` | Pencatatan status keabsahan alamat surel pengguna |

---

## 4. Keuntungan Pemisahan Tanggung Jawab (Separation of Concerns)

- Package `mixudev/laravel-authentication` fokus menangani **identitas & sesi pengguna** (login, register, 2FA OTP, remember-me, lockout lokal).
- Package `mixudev/security-defense` fokus menangani **keamanan jaringan & korelasi ancaman** (WAF, pemblokiran IP, mitigasi DDoS, analisis epistemik, notifikasi Telegram admin).
- Keduanya berkomunikasi murni melalui standar event Laravel tanpa ada dependensi sirkular.
