# Integrasi Audit Perubahan Database & Deteksi Tamper Burp Suite

Fitur **Database Change Monitoring & Tamper Intelligence** pada `mixudev/security-defense` dirancang untuk mencatat siklus hidup mutasi data Eloquent (`created`, `updated`, `deleted`, `restored`), menangkap jejak pelaku (*actor*), URL dan HTTP method asal, snapshot payload request, serta mendeteksi serangan manipulasi parameter proxy seperti **Burp Suite** atau *Mass Assignment*.

---

## 1. Metode Pemasangan

Terdapat dua pendekatan integrasi yang fleksibel sesuai kebutuhan arsitektur aplikasi Anda:

### Metode A: Menggunakan Trait `HasSecurityAudit` pada Model (Direkomendasikan)
Cukup pasang Trait `HasSecurityAudit` pada model Eloquent yang ingin dipantau.

```php
namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Mixudev\SecurityDefense\Support\Traits\HasSecurityAudit;

class Product extends Model
{
    use HasSecurityAudit;

    protected $fillable = [
        'title',
        'price',
        'stock',
        'is_published',
    ];

    /**
     * Opsional: Kolom yang DIKECUALIKAN dari audit log.
     * Default bawaan: updated_at, created_at.
     */
    protected array $securityAuditExclude = [
        'updated_at',
        'last_viewed_at',
    ];

    /**
     * Opsional: Kolom sensitif yang nilainya WAJIB DISAMARKAN menjadi [REDACTED].
     * Default bawaan mencakup: password, api_token, secret, cvv, credit_card.
     */
    protected array $securityAuditMasked = [
        'supplier_cost',
        'secret_vendor_key',
    ];
}
```

### Metode B: Konfigurasi Global Tanpa Mengubah Model (`auto_watch_models`)
Jika Anda tidak ingin menyentuh file model (misal model vendor atau legacy), cukup daftarkan class model di `config/security-defense.php`:

```php
'data_audit' => [
    'enabled' => true,

    'auto_watch_models' => [
        \App\Models\User::class,
        \App\Models\Order::class,
        \App\Models\Invoice::class,
        \App\Models\Transaction::class,
    ],
],
```
Package secara otomatis mengaitkan event lifecycle Eloquent saat aplikasi boot.

---

## 2. Cara Kerja Deteksi Manipulasi Burp Suite

Ketika penyerang meng-intercept request via **Burp Suite**, **OWASP ZAP**, atau script automasi:

1. **Mass Assignment / Sensitive Attribute Injection**:
   - Form frontend hanya menyediakan input untuk `name` dan `email`.
   - Penyerang menyisipkan parameter `is_admin=1`, `role=superadmin`, `status=active`, atau `balance=5000000` di dalam body HTTP request.
   - `DataAuditService` membandingkan daftar kolom yang termutasi pada model dengan input pada `request()->all()`. Jika ada kolom dalam daftar `sensitive_watch_fields` yang termutasi akibat kiriman payload HTTP, mutasi langsung ditandai dengan flag:
     ```php
     $audit->is_tampered === true;
     // tamper_reasons: ["Sensitive column 'is_admin' was altered directly from HTTP request payload..."]
     ```
2. **Unguarded Non-Fillable Mutation**:
   - Jika model memiliki whitelist `$fillable`, dan ada kolom di luar whitelist yang termutasi karena disuntikkan via payload, flag tamper akan aktif.
3. **Canary / Honeypot Traps**:
   - Sistem menyediakan field jebakan bot (default: `_system_sync_token`).
   - Jika bot/script mengisi field tersembunyi ini, flag tamper langsung diaktifkan.

---

## 3. Konfigurasi `config/security-defense.php`

```php
'data_audit' => [
    'enabled' => env('SECURITY_DATA_AUDIT_ENABLED', true),
    'table' => 'security_data_audits',
    'alert_on_tampering' => true, // Mengirimkan alert ke SIEM jika manipulasi terdeteksi

    'auto_watch_models' => [
        // Daftar model yang diawasi otomatis
    ],

    // Kolom yang selalu disamarkan nilainya (Zero-Leakage)
    'default_masked_fields' => [
        'password',
        'password_hash',
        'remember_token',
        'api_token',
        'secret',
        'two_factor_secret',
        'credit_card',
        'cvv',
    ],

    // Kolom yang diabaikan dari pencatatan diff
    'default_excluded_fields' => [
        'updated_at',
        'created_at',
    ],

    // Kolom sensitif yang memicu BURP TAMPER DETECTED jika dikirim via HTTP
    'sensitive_watch_fields' => [
        'is_admin',
        'role',
        'role_id',
        'permissions',
        'balance',
        'credit',
        'status',
        'email_verified_at',
    ],

    // Field jebakan bot
    'honeypot_field' => '_system_sync_token',

    // Batasan ukuran payload snapshot (Anti-DoS)
    'max_payload_snapshot_bytes' => 8192,

    // Retensi riwayat (hari)
    'retention_days' => 90,
],
```

---

## 4. Query Data Audit via Eloquent

Model `Mixudev\SecurityDefense\Models\SecurityDataAudit` menyediakan berbagai scope siap pakai:

```php
use Mixudev\SecurityDefense\Models\SecurityDataAudit;

// 1. Ambil mutasi yang terindikasi manipulasi Burp Suite
$tamperedAudits = SecurityDataAudit::tampered()->latest()->get();

// 2. Ambil riwayat perubahan khusus untuk entitas tertentu
$userAudits = SecurityDataAudit::forAuditable(\App\Models\User::class, '42')->get();

// 3. Ambil seluruh aksi yang dilakukan oleh Admin ID 1
$adminActions = SecurityDataAudit::forActor('1', \App\Models\User::class)->get();

// 4. Membaca diff nilai
foreach ($tamperedAudits as $audit) {
    dump([
        'event' => $audit->event,
        'old' => $audit->old_values,
        'new' => $audit->new_values,
        'modified' => $audit->modified_fields,
        'reasons' => $audit->tamper_reasons,
        'origin_url' => $audit->request_url,
        'payload_snapshot' => $audit->payload_snapshot,
    ]);
}
```

---

## 5. Pemantauan di Dashboard

Buka dashboard monitoring pada URL `/security-defense/data-audits`:
- **Badge Merah Berkedip "BURP TAMPER DETECTED"**: Mengindikasikan bahwa data berhasil termutasi namun melalui intervensi parameter payload yang mencurigakan.
- **Side-by-Side Diff Inspector**: Klik tombol **View Diff** untuk melihat tabel perbandingan nilai sebelum vs sesudah dengan penanda visual warna hijau/merah.
- **Request Payload Snapshot**: Klik tombol **Payload** untuk melihat JSON body request asli saat aksi dikirimkan ke server.
