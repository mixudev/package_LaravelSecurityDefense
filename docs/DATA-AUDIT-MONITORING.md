# Database Mutation & Burp Suite Tamper Monitoring (Dokumentasi Penggunaan)

Paket **`mixudev/security-defense`** menyediakan sistem audit perubahan data tingkat lanjut (*Data Integrity & Audit Intelligence*) yang tidak hanya mencatat riwayat mutasi database (siapa, apa, kapan, di mana), tetapi juga secara proaktif mendeteksi manipulasi parameter dan serangan *Mass Assignment* via **Burp Suite** atau tools proxy sejenis.

---

## 1. Kemampuan & Fitur Utama (Bisa Apa Saja?)

1. **Pencatatan Audit Otomatis (Lifecycle-Aware)**:
   - Mencatat event `created`, `updated`, `deleted`, dan `restored` pada model Eloquent.
   - Menyimpan nilai lama (*old values*), nilai baru (*new values*), dan daftar kolom yang termutasi (*modified fields*).
2. **Konteks Request Penuh**:
   - URL request lengkap, HTTP method (`POST`, `PUT`, `PATCH`, `DELETE`, `CLI`).
   - Route name Laravel (misal `admin.users.update`).
   - IP address pelaku dan User-Agent.
   - Aktor yang login (`actor_id` dan `actor_type` via `Auth::user()`) atau penanda `CLI/System`.
   - Snapshot HTTP Request Payload asli pada detik saat mutasi terjadi.
3. **Deteksi Manipulasi Burp Suite & Parameter Injeksi**:
   - Mendeteksi jika kolom sensitif (seperti `is_admin`, `role`, `balance`, `status`) diubah secara diam-diam melalui HTTP input parameter.
   - Mendeteksi mutasi atribut yang di-bypass di luar whitelist `$fillable` model.
   - Mendeteksi bot/form-grabber otomatis via *Honeypot Canary field*.
4. **Zero-Leakage Guarantee (Keamanan Tingkat Tinggi)**:
   - Nilai kolom kredensial (seperti `password`, `token`, `secret`, `credit_card`) **otomatis disanitasi menjadi `[REDACTED]`** sebelum data menyentuh database audit.
   - Mencegah *Stored XSS* di dashboard: semua output payload dan diff menggunakan enkapsulasi dan escaping Blade baku.
   - Mencegah *Disk Flooding (DoS)*: snapshot request payload dibatasi secara otomatis (maksimal 8KB).

---

## 2. Cara Penggunaan pada Model

Ada dua cara untuk memantau model:

### Cara 1: Menggunakan Trait `HasSecurityAudit` (Rekomendasi)
Cukup pasang Trait `HasSecurityAudit` pada model yang ingin Anda pantau:

```php
namespace App\Models;

use Illuminate\Foundation\Auth\User as Authenticatable;
use Mixudev\SecurityDefense\Support\Traits\HasSecurityAudit;

class User extends Authenticatable
{
    use HasSecurityAudit;

    protected $fillable = [
        'name',
        'email',
        'password',
    ];

    /**
     * Kolom opsional yang ingin DIKECUALIKAN dari audit
     * (Default sistem: updated_at, created_at)
     */
    protected array $securityAuditExclude = [
        'updated_at',
        'remember_token',
    ];

    /**
     * Kolom sensitif yang nilainya WAJIB DI-MASK menjadi [REDACTED]
     * (Default sistem mencakup password, api_token, cvv, dll)
     */
    protected array $securityAuditMasked = [
        'password',
        'two_factor_secret',
    ];
}
```

### Cara 2: Konfigurasi Global Tanpa Menyentuh Model (`auto_watch_models`)
Jika Anda tidak ingin mengubah kode model aplikasi host, Anda cukup mendaftarkan class model di `config/security-defense.php`:

```php
'data_audit' => [
    'enabled' => true,
    
    'auto_watch_models' => [
        \App\Models\User::class,
        \App\Models\Order::class,
        \App\Models\Role::class,
    ],
],
```

---

## 3. Cara Mengatur Kolom yang Dipantau

Semua aturan kolom dapat dikustomisasi di file `config/security-defense.php`:

```php
'data_audit' => [
    'enabled' => env('SECURITY_DATA_AUDIT_ENABLED', true),
    'alert_on_tampering' => true,

    // 1. Kolom yang SELALU disamarkan nilainya demi privasi data & GDPR
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

    // 2. Kolom yang diabaikan agar log audit tidak bising
    'default_excluded_fields' => [
        'updated_at',
        'created_at',
    ],

    // 3. Kolom krusial: Jika diubah langsung via HTTP payload, sistem akan
    // memicu status "TAMPER DETECTED" (Burp Suite Manipulation Alert)
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

    // 4. Field Honeypot rahasia untuk menangkap bot form-grabber
    'honeypot_field' => '_system_sync_token',

    // 5. Batas aman ukuran payload (Bytes) untuk mencegah disk filling DoS
    'max_payload_snapshot_bytes' => 8192,

    // 6. Umur retensi data (hari)
    'retention_days' => 90,
],
```

---

## 4. Cara Melihat & Mengakses Data Audit

### A. Melalui Security Dashboard
Buka URL: `/security-defense/data-audits` (hanya dapat diakses secara lokal atau IP whitelist).
Fitur yang tersedia:
- **Badge Merah Berkedip "BURP TAMPER DETECTED"**: Menandai request yang terindikasi manipulasi proxy.
- **Side-by-Side Diff Inspector**: Klik tombol **"View Diff"** untuk melihat perubahan nilai lama vs baru dengan highlight warna.
- **Request Payload Inspector**: Klik tombol **"Payload"** untuk melihat format JSON payload asli yang dikirim penyerang saat aksi dilakukan.

### B. Melalui Eloquent Query di Kode Host
Model `Mixudev\SecurityDefense\Models\SecurityDataAudit` menyediakan helper scopes yang mudah:

```php
use Mixudev\SecurityDefense\Models\SecurityDataAudit;

// Ambil semua perubahan yang terindikasi manipulasi Burp Suite
$tampered = SecurityDataAudit::tampered()->latest()->get();

// Ambil riwayat perubahan khusus untuk User tertentu
$userAudits = SecurityDataAudit::forAuditable(User::class, '15')->get();

// Ambil mutasi yang dilakukan oleh Admin dengan ID 1
$adminActions = SecurityDataAudit::forActor('1', Admin::class)->get();
```

---

## 5. Pertimbangan & Jaminan Keamanan (Security Hardening)

1. **Non-Blocking / Fail-Safe**:
   - Jika terjadi error pada proses audit (misal disk penuh), transaksi bisnis utama user **TIDAK AKAN CRASH** karena dilindungi blok fail-safe.
2. **Anti-Leakage Data Sensitif**:
   - Password dan secret tidak pernah masuk ke log dalam bentuk plaintext.
3. **Anti-ReDoS & Bounded Memory**:
   - Payload JSON diperiksa dan dipotong sebelum disimpan untuk mencegah memory exhaustion.
4. **Isolasi Dashboard**:
   - Halaman monitoring terlindungi di balik middleware `EnsureLocalAccess`.
