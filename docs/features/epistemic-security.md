# Epistemic Autonomous Security Defense

Fitur ini memberi analisis ancaman berbasis bukti, confidence, risk, policy, memory, dan provider AI opsional. Fitur bersifat opt-in, eksperimental, dan belum siap produksi. Jangan jadikan assessment sebagai satu-satunya dasar tindakan destruktif atau penolakan akses.

Pipeline ini tidak menggantikan `record()`/`processEvent()`. Default `epistemic.enabled=false` dan `epistemic.response.enabled=false`; aplikasi lama tetap memakai jalur pertahanan lama.

## Aktivasi

Tambahkan konfigurasi berikut pada `config/security-defense.php`:

```php
'epistemic' => [
    'enabled' => false,
],
```

Default `false` menjaga perilaku aplikasi lama. Pipeline `record()` tetap dipakai dan tidak digantikan. Aktifkan `true` hanya setelah menguji hasil, latency, storage, dan policy pada lingkungan yang sesuai.

## API analisis

API publik `SecurityDefense::analyze(AnalysisContext|array $context): ThreatAssessment` menerima `AnalysisContext`. Bentuk array publik juga didukung sebagai daftar event (`array<SecurityEvent|array<string, mixed>>`), bukan array dengan key `events`/`evidence`/`subject`/`windowSeconds`.

Untuk konteks lengkap dan evidence tambahan, buat `AnalysisContext` secara eksplisit.

### Analisis dengan DTO

```php
use Mixudev\SecurityDefense\DTO\SecurityEvent;
use Mixudev\SecurityDefense\Epistemic\DTO\AnalysisContext;
use Mixudev\SecurityDefense\Support\Facades\SecurityDefense;

$event = new SecurityEvent(
    ip: '203.0.113.10',
    identifier: 'user-42',
    eventType: 'LoginFailed',
    userAgent: 'ExampleClient/1.0',
    metadata: ['source' => 'auth'],
);

$context = new AnalysisContext(
    events: [$event],
    evidence: [],
    subject: 'user-42',
    windowSeconds: 900,
);

$assessment = SecurityDefense::analyze($context);
```

### Analisis dari array

Bentuk array menerima daftar event saja (`array<SecurityEvent|array<string, mixed>>`), bukan object `AnalysisContext`. Untuk menetapkan evidence, subject, atau windowSeconds, buat `AnalysisContext` secara eksplisit.

```php
use Mixudev\SecurityDefense\Support\Facades\SecurityDefense;

$assessment = SecurityDefense::analyze([
    [
        'ip' => '203.0.113.10',
        'identifier' => 'user-42',
        'eventType' => 'LoginFailed',
        'userAgent' => 'ExampleClient/1.0',
        'metadata' => ['source' => 'auth'],
    ],
]);
```

`SecurityEvent` menormalisasi event telemetry. Jangan masukkan password, token, cookie, authorization header, atau secret ke metadata. Input tetap harus diperlakukan sebagai data tidak tepercaya.

## Membaca ThreatAssessment

Gunakan accessor yang tersedia. Nilai `risk()` dan `confidence()` adalah value object; gunakan `toFloat()`. `decision()` dapat bernilai `null`.

```php
$risk = $assessment->risk()->toFloat();
$confidence = $assessment->confidence()->toFloat();
$hypotheses = $assessment->hypotheses();
$evidence = $assessment->evidence();
$decision = $assessment->decision();

$summary = $assessment->toArray();
```

Accessors memiliki makna berbeda:

- `risk()`: skor risiko agregat assessment.
- `confidence()`: keyakinan agregat terhadap hipotesis.
- `hypotheses()`: daftar `ThreatBelief` hasil korelasi.
- `evidence()`: bukti yang dipakai analisis.
- `decision()`: keputusan dari policy engine, bila tersedia.
- `toArray()`: representasi ringkas assessment, termasuk risk, confidence, jumlah evidence, dan action decision.

Jangan menyamakan risk tinggi dengan confidence tinggi. Sinyal kuat dapat tetap memiliki konteks yang tidak lengkap.

## Feedback terverifikasi

Gunakan API publik `SecurityDefense::recordFeedback` dengan `ThreatBelief` dari assessment. `FeedbackHandler` juga tersedia untuk integrasi langsung:

```php
use Mixudev\SecurityDefense\Epistemic\Feedback\FeedbackHandler;
use Mixudev\SecurityDefense\Epistemic\Memory\ExperienceMemory;

$hypotheses = $assessment->hypotheses();

if ($hypotheses !== []) {
    $handler = new FeedbackHandler(app(ExperienceMemory::class));
    $handler->record($hypotheses[0], 'confirmed_attack');
}
```

`SecurityDefense::recordFeedback(ThreatBelief $belief, string $outcome, ?string $feedbackId = null): void` adalah API publik. Outcome yang diterima hanya `'confirmed_attack'` dan `'false_positive'`; `'confirmed'` tidak valid. `feedbackId` opsional memberi deduplikasi feedback.

Catat feedback hanya jika outcome sudah diverifikasi oleh proses aplikasi. Feedback salah dapat memengaruhi memory dan analisis berikutnya.

## Arsitektur dan bounded graph traversal

Komponen berada di `src/Epistemic`.

```text
AnalysisContext
  -> evidence collection
  -> korelasi hipotesis dan graph traversal terbatas
  -> confidence
  -> risk
  -> policy decision
  -> ThreatAssessment
```

Korelasi menggunakan jendela `windowSeconds` dan traversal graph yang dibatasi. Batas ini mengurangi risiko penggunaan CPU/memori tak terkendali, tetapi juga berarti bukti di luar batas dapat tidak terhubung. Fitur bukan query bebas seluruh histori keamanan.

## Provider AI

Provider AI adalah batas pemasok evidence. Provider menerima `AnalysisContext` dan mengembalikan bukti; provider tidak menjadi pemilik keputusan. Provider default adalah `NullAiProvider`, sehingga tidak menghasilkan evidence AI. Evidence AI yang lolos validasi dapat ikut korelasi dan memengaruhi assessment, tetapi tetap advisory: AI tidak menjadi otoritas keputusan.

Policy engine tetap menentukan `decision()`. AI tidak boleh langsung memblokir request, mengarantina IP, mengubah risk secara langsung, atau melewati sanitization. Jika `epistemic.response.enabled=false` (default), tidak ada response enforcement. Enforcement memerlukan `DecisionResponseAdapterInterface` yang dikonfigurasi dan opt-in eksplisit; adapter default `NoopResponseAdapter` tidak melakukan enforcement. Integrasi provider nyata harus memakai binding aplikasi, mengirim data minimum, membatasi timeout/retry, dan menangani kegagalan sebagai provider tidak tersedia.

Package tidak menyediakan endpoint AI atau vendor tertentu. Feedback tersedia melalui `SecurityDefense::recordFeedback()` dan `SecurityDefenseManager::recordFeedback()`; keduanya menerima outcome terverifikasi `'confirmed_attack'` atau `'false_positive'` serta `feedbackId` opsional.

## Batas implementasi

- `AnalysisContext` membatasi `max_events=500` dan `max_evidence=500`; metadata dibatasi `max_metadata_bytes=4096`.
- Graph dibatasi `max_depth=8`, `max_nodes=500`, dan `window_seconds=900` secara konfigurasi. `windowSeconds` pada konteks default 900 detik. Timestamp masa depan evidence AI lebih dari 60 detik ditolak.
- Memory berbasis cache menyimpan paling banyak `max_patterns=10000` pola dengan retensi `retention_days=30`. Penyimpanan memakai cache lock; fallback memakai counter atomik bila lock tidak tersedia. `feedbackId` mencegah replay feedback selama retensi.
- Batas dapat mengurangi cakupan; event/evidence di luar batas, timestamp kedaluwarsa, atau rantai graph yang terlalu dalam dapat tidak terhubung.

## Keterbatasan keamanan

- False positive dan false negative tetap mungkin.
- Telemetry hilang atau terlambat dapat mengurangi kualitas evidence dan confidence.
- Risk, confidence, dan decision bukan bukti forensik atau atribusi penyerang.
- Provider AI dapat menghadirkan prompt injection, kebocoran data, biaya, dan kegagalan jaringan.
- Memory dapat belajar dari feedback yang keliru.
- Jangan jadikan satu assessment sebagai dasar tunggal tindakan destruktif atau penolakan akses tanpa kontrol policy dan verifikasi tambahan.
- Sanitization, batas ukuran input, jendela waktu, dan batas traversal tetap penting pada data tidak tepercaya.

## Upgrade notes

- Jalur `record()` lama tetap tersedia setelah upgrade.
- Pertahankan `security-defense.epistemic.enabled=false` saat migrasi.
- Uji kompatibilitas `AnalysisContext`, `SecurityEvent`, `SecurityDefense::analyze`, seluruh accessor `ThreatAssessment`, binding AI, dan `FeedbackHandler` setelah upgrade.
- Gunakan accessor publik, bukan properti internal atau kelas internal di `src/Epistemic`.
- Tinjau ulang policy, retention memory, logging, sanitization, dan konfigurasi provider pada setiap upgrade.
