# Epistemic Autonomous Security Defense

Fitur ini memberi analisis ancaman berbasis bukti, confidence, risk, policy, memory, dan provider AI opsional. Fitur bersifat opt-in.

## Aktivasi

Tambahkan konfigurasi berikut pada `config/security-defense.php`:

```php
'epistemic' => [
    'enabled' => false,
],
```

Default `false` menjaga perilaku aplikasi lama. Pipeline `record()` tetap dipakai dan tidak digantikan. Aktifkan `true` hanya setelah menguji hasil, latency, storage, dan policy pada lingkungan yang sesuai.

## API analisis

API publik baru menerima `AnalysisContext` atau array yang ditentukan implementasi rencana dan mengembalikan `ThreatAssessment`.

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

Gunakan bentuk array hanya untuk input yang mengikuti field `AnalysisContext` (`events`, `evidence`, `subject`, `windowSeconds`):

```php
use Mixudev\SecurityDefense\Support\Facades\SecurityDefense;

$assessment = SecurityDefense::analyze([
    'events' => [],
    'evidence' => [],
    'subject' => 'user-42',
    'windowSeconds' => 900,
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

Tidak ada asumsi tentang method feedback pada manager. Gunakan `FeedbackHandler` yang tersedia bersama `ThreatBelief` dari assessment:

```php
use Mixudev\SecurityDefense\Epistemic\Feedback\FeedbackHandler;
use Mixudev\SecurityDefense\Epistemic\Memory\ExperienceMemory;

$hypotheses = $assessment->hypotheses();

if ($hypotheses !== []) {
    $handler = new FeedbackHandler(app(ExperienceMemory::class));
    $handler->record($hypotheses[0], 'confirmed');
}
```

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

Provider AI adalah batas pemasok evidence. Provider menerima `AnalysisContext` dan mengembalikan bukti; provider tidak menjadi pemilik keputusan. Provider default adalah `NullAiProvider`, sehingga tidak menghasilkan evidence AI.

Policy engine tetap menentukan `decision()`. AI tidak boleh langsung memblokir request, mengarantina IP, mengubah risk, atau melewati sanitization. Integrasi provider nyata harus memakai binding aplikasi, mengirim data minimum, membatasi timeout/retry, dan menangani kegagalan sebagai provider tidak tersedia.

Jangan menganggap package menyediakan endpoint AI, vendor, format credential, atau public method manager untuk feedback. Detail itu berada di luar kontrak API yang didokumentasikan.

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
