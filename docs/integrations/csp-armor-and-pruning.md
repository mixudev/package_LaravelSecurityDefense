# Panduan Integrasi: Content Security Policy (CSP) Armor & Data Hygiene

Modul `ContentSecurityPolicyArmor` melindungi aplikasi dari serangan XSS (Cross-Site Scripting) secara transparan di balik layar (zero-code changes).

---

## 1. Daftar Kebutuhan (Requirements Checklist)

Gunakan checklist ini untuk mengaktifkan seluruh fitur keamanan response dan data hygiene:

- [ ] **PHP 8.2+** dan **Laravel 11.x, 12.x, atau 13.x**.
- [ ] **Publish Konfigurasi**: `config/security-defense.php` sudah dipublish.
- [ ] **Registrasi Middleware CSP Armor**: Daftarkan `ContentSecurityPolicyArmor` di HTTP Kernel atau `bootstrap/app.php`.
- [ ] **Jadwalkan Pruning Log**: Tambahkan `security-defense:prune` ke Laravel Task Scheduler.
- [ ] **Gunakan Safe Payload Accessor**: Di custom dashboard atau API eksternal, konsumsi `$audit->safe_payload` alih-alih `$audit->payload_snapshot` mentah.

---

## 2. Cara Mengaktifkan CSP Armor di Laravel

### Laravel 11 / 12 / 13 (`bootstrap/app.php`)
```php
use Mixudev\SecurityDefense\Middleware\ContentSecurityPolicyArmor;

return Application::configure(basePath: dirname(__DIR__))
    ->withMiddleware(function (Middleware $middleware) {
        // Pasang secara global atau pada web group
        $middleware->web(append: [
            ContentSecurityPolicyArmor::class,
        ]);
    })
    ->create();
```

### Konfigurasi Policy (`config/security-defense.php`)
```php
'csp_armor' => [
    'enabled' => true,
    'report_only' => false, // Set true jika ingin uji coba tanpa memblokir
    'policy' => null,       // null menggunakan zero-compromise default policy dengan nonce
],
```

---

## 3. Otomasi Pembersihan Data untuk Skala Jutaan User (Data Pruning)

Ketika aplikasi memproses jutaan request, data log audit dapat dibersihkan otomatis dengan command:

```bash
# Uji coba melihat jumlah data yang akan dihapus
php artisan security-defense:prune --dry-run

# Eksekusi pembersihan
php artisan security-defense:prune
```

### Menjadwalkan Otomatis di Scheduler (`routes/console.php`)
```php
use Illuminate\Support\Facades\Schedule;

Schedule::command('security-defense:prune')->dailyAt('02:00');
```

---

## 4. Akses Data Aman untuk Custom Dashboard

Jika Anda membuat tampilan dashboard sendiri menggunakan data `SecurityDataAudit`:

```blade
<!-- AMAN: Nilai string otomatis di-escape terhadap tag HTML & script -->
@foreach($audit->safe_payload as $key => $value)
    <div>{{ $key }}: {{ is_array($value) ? json_encode($value) : $value }}</div>
@endforeach
```
