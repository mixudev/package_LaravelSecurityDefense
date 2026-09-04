# 05 — Kustomisasi Lanjutan

Panduan mengkustomisasi package melampaui konfigurasi dasar: tuning rule,
extend detection rule, channel kustom, threat source kustom, dan skenario tuning.

---

## 1. Customisasi Konfigurasi (Config File)

Setelah publish config (`config/security-defense.php`), nilai bawaan bisa diubah.
Template lengkap ada di [06-security-hardening.md](./06-security-hardening.md)
untuk produksi. Berikut bagian yang paling sering di-tuning:

```php
// config/security-defense.php

// Skor gabungan untuk memicu compound threat (default 100)
'detection' => [
    'scoring' => [
        'threshold' => 100,
        'window' => 900,
        'weights' => [
            'brute_force' => 35,
            'credential_stuffing' => 45,
            'distributed_spray' => 30,
            'rate_limit_bypass' => 20,
            'payload_injection' => 50,
            'impossible_travel' => 35,
            'path_reconnaissance' => 30,
            'user_agent_anomaly' => 25,
        ],
    ],
    'rules' => [
        'brute_force' => [
            'threshold' => 10,   // ambang gagal login
            'window' => 60,      // detik
            'severity' => 'high',
            'events' => ['LoginFailed', 'OTP_FAILED'],
        ],
        // ... rule lain
    ],
],
```

Gunakan runtime config `config(['security-defense...' => ...])` jika ingin
tuning dinamis (bedakan per environment).

---

## 2. Membuat Rule Deteksi Kustom

Extension rule memungkinkan deteksi pola baru. Buat class yang memperluas
`AbstractDetectionRule` dan daftarkan ke service container.

### Langkah

1. **Buat class rule** (mis. `app/Security/Rules/DarkWebMonitorRule.php`):

```php
<?php

namespace App\Security\Rules;

use Mixudev\SecurityDefense\Rules\AbstractDetectionRule;
use Mixudev\SecurityDefense\ValueObjects\SecurityEvent;
use Mixudev\SecurityDefense\ValueObjects\SecurityThreat;

class DarkWebMonitorRule extends AbstractDetectionRule
{
    public function detect(SecurityEvent $event): ?SecurityThreat
    {
        // Logika deteksi Anda...
        if ($event->eventType === 'CredentialLeak' && $event->ip) {
            return new SecurityThreat(
                ruleIdentifier: 'dark_web_leak',
                severity: 'critical',
                threatType: 'credential_leak',
                ip: $event->ip,
                identifier: $event->identifier,
                score: 60,
                metadata: ['source' => 'dark_web']
            );
        }

        return null;
    }
}
```

> Lihat contoh implementasi di `src/Rules/*Rule.php` untuk referensi struktur
> dan ValueObject yang tersedia (`SecurityThreat`, `SecurityEvent`).

2. **Daftarkan ke AnomalyDetector** (override binding di `AppServiceProvider::register()`):

```php
use App\Security\Rules\DarkWebMonitorRule;
use Mixudev\SecurityDefense\Contracts\ThreatDetector;
use Mixudev\SecurityDefense\Detection\AnomalyDetector;

$this->app->singleton(ThreatDetector::class, function ($app) {
    return new AnomalyDetector([
        $app->make(\Mixudev\SecurityDefense\Rules\BruteForceRule::class),
        // ... semua rule bawaan ...
        $app->make(DarkWebMonitorRule::class), // rule kustom Anda
    ]);
});
```

> Catatan: Saat menimpa `ThreatDetector`, sertakan SEMUA rule bawaan yang
> diinginkan (penimpaan menggantikan daftar default dari provider).

---

## 3. Membuat Channel Notifikasi Kustom

Tambahkan channel baru (mis. Slack, WhatsApp) dengan mengimplementasikan kontrak
`Mixudev\SecurityDefense\Contracts\AlertChannel`:

```php
<?php

namespace App\Security\Channels;

use Illuminate\Support\Facades\Http;
use Mixudev\SecurityDefense\Contracts\AlertChannel;
use Mixudev\SecurityDefense\Models\SecurityAlert;

class SlackChannel implements AlertChannel
{
    public function __construct(private readonly array $config) {}

    public function identifier(): string
    {
        return 'slack';
    }

    public function isEnabled(): bool
    {
        return $this->config['enabled'] ?? false;
    }

    public function isConfigured(): bool
    {
        return filled($this->config['webhook_url'] ?? null);
    }

    public function send(SecurityAlert $alert): bool
    {
        $payload = ['text' => "[{$alert->severity}] {$alert->threat_type} — {$alert->fingerprint}"];
        Http::timeout(5)
            ->post($this->config['webhook_url'], $payload)
            ->throw();

        return true;
    }
}
```

Kontrak `AlertChannel` (`src/Contracts/AlertChannel.php`) mewajibkan 4 method:
`identifier(): string`, `isEnabled(): bool`, `isConfigured(): bool`,
`send(SecurityAlert $alert): bool`. Lihat `src/Channels/*` untuk contoh channel bawaan.

2. **Bind & daftarkan ke AlertDispatcher** (`AppServiceProvider`):

```php
use App\Security\Channels\SlackChannel;
use Mixudev\SecurityDefense\Services\AlertDispatcher;

$this->app->singleton(SlackChannel::class, fn () => new SlackChannel([
    'enabled' => config('services.slack.enabled'),
    'webhook_url' => config('services.slack.webhook_url'),
]));

$this->app->extend(AlertDispatcher::class, function (AlertDispatcher $dispatcher, $app) {
    $dispatcher->registerChannel($app->make(SlackChannel::class));
    return $dispatcher;
});
```

3. Channel baru otomatis muncul di dashboard (grid channel) & test diagnostic
   jika mengimplementasikan kontrak dengan benar.

---

## 4. Threat Source Kustom (Ingestion)

Secara default telemetry dikirim via `SecurityDefense::record()` (menerima array
atau instance `ThreatSource`) atau dari middleware `RequestThreatScanner`.
Untuk mengintegrasikan sumber lain (message queue, log parser, dll), kirim
`GenericArraySource` ke engine:

```php
use Mixudev\SecurityDefense\Sources\GenericArraySource;
use Mixudev\SecurityDefense\Support\Facades\SecurityDefense;

// Bangun source dari data eksternal
$source = new GenericArraySource([
    'ip' => '203.0.113.7',
    'identifier' => 'user@example.com',
    'eventType' => 'LoginFailed',
    'userAgent' => 'Mozilla/5.0 ...',
    'metadata' => ['ua_family' => 'Chrome'],
]);

// Kirim lewat facade record()
SecurityDefense::record($source);
```

Untuk pemrosesan event DTO langsung, gunakan `SecurityDefense::processEvent(SecurityEvent $event)`.

---

## 5. Skenario Tuning Umum

| Kebutuhan | Config yang diubah |
|-----------|--------------------|
| Lebih agresif terhadap brute force | Turunkan `brute_force.threshold` (mis. 5), naikkan severity |
| Kurangi false-positive impossible travel | Naikkan `impossible_travel.max_speed_kmh` (mis. 1200) |
| Serangan lebih lama dideteksi | Naikkan `window` tiap rule / `scoring.window` |
| Matikan satu vektor | `enabled => false` pada rule tsb |
| Hanya log (tidak block) payload mencurigakan | `middleware.payload_scanner.action => 'log_only'` |
| Blok visitor tanpa User-Agent | `SECURITY_DEFENSE_BLOCK_EMPTY_UA=true` |
| Quarantine lebih lama | `middleware.quarantine.duration` (detik) |

---

## 6. Mengekspos Alerts Model

Model `SecurityAlert` hijau = mudah di-query dari aplikasi Anda. Scope bawaan:

```php
use Mixudev\SecurityDefense\Models\SecurityAlert;

SecurityAlert::new()->get();            // status 'new'
SecurityAlert::acknowledged()->get();   // status 'acknowledged'
SecurityAlert::resolved()->get();       // status 'resolved'
SecurityAlert::severity('critical')->get();
```

Scope dapat di-rantai, mis. `SecurityAlert::new()->severity('critical')->get()`.

Lanjut ke [06-security-hardening.md](./06-security-hardening.md).
