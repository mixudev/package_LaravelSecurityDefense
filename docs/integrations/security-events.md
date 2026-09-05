# Panduan Integrasi: Security Events & Asynchronous Queuing

Package `mixudev/security-defense` menganut prinsip **Decoupled Telemetry & Graduated Response**. Ketika insiden terjadi, package memicu Event resmi Laravel agar aplikasi host dapat merespons sesuai logika bisnis tanpa harus mengubah core auth.

---

## 1. Daftar Kebutuhan (Requirements Checklist)

- [ ] **Worker Antrean Aktif**: Jalankan `php artisan queue:work` jika mengaktifkan `data_audit.queue.enabled`.
- [ ] **Konfigurasi Queue**: Tentukan connection dan queue khusus (`security-audit`).
- [ ] **Registrasi Event Listener**: Daftarkan listener di `EventServiceProvider` atau `AppServiceProvider`.

---

## 2. Asynchronous Queue Processing (Skalabilitas Jutaan Mutasi)

Untuk aplikasi dengan volume transaksi tinggi, aktifkan queue di `config/security-defense.php`:

```php
'data_audit' => [
    'queue' => [
        'enabled' => true, // default: false (synchronous)
        'connection' => 'redis',
        'queue' => 'security-audit',
    ],
],
```

Dengan opsi ini, penulisan snapshot payload 8KB dialihkan ke background job `ProcessSecurityDataAuditJob`, menjaga response time HTTP tetap < 1ms.

---

## 3. Event Resmi yang Disediakan Package

### A. `SecuritySessionCompromised`
Ditembakkan saat `SessionFingerprintRule` mendeteksi cookie valid digunakan dengan subnet IP drastis atau User-Agent yang tidak wajar (indikasi infostealer malware seperti RedLine/Lumma).

```php
use Illuminate\Support\Facades\Event;
use Mixudev\SecurityDefense\Events\SecuritySessionCompromised;

Event::listen(SecuritySessionCompromised::class, function (SecuritySessionCompromised $event) {
    // Contoh tindakan: Cabut personal access tokens Sanctum
    if ($user = \App\Models\User::find($event->userId)) {
        $user->tokens()->delete();
    }
});
```

### B. `SecurityParameterTampered`
Ditembakkan saat `DataAuditService` menemukan injeksi parameter sensitif (`is_admin`, `role`, `balance`) via HTTP request.

```php
use Mixudev\SecurityDefense\Events\SecurityParameterTampered;

Event::listen(SecurityParameterTampered::class, function (SecurityParameterTampered $event) {
    // Audit model yang dimanipulasi
    Log::alert("Percobaan mass assignment terdeteksi pada {$event->audit->auditable_type} ID {$event->audit->auditable_id}");
});
```

### C. `IpQuarantined`
Ditembakkan saat IP penyerang dijebloskan ke dalam karantina Fail2Ban.

```php
use Mixudev\SecurityDefense\Events\IpQuarantined;

Event::listen(IpQuarantined::class, function (IpQuarantined $event) {
    // Contoh: Kirim sinyal ke Cloudflare API / AWS WAF untuk blokir di level Edge DNS
});
```
