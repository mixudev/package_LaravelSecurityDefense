# Epistemic Autonomous Security Defense

Dokumen internal ini menjelaskan arsitektur analisis epistemik pada `mixudev/security-defense`. Fitur ini menambahkan penalaran berbasis bukti tanpa mengganti pipeline pertahanan lama.

## Status dan batas opt-in

Pipeline lama `record()` tetap menjadi jalur default dan tetap berjalan seperti sebelumnya. Analisis epistemik memakai jalur baru `analyze()` dan **tidak aktif secara default**.

Aktifkan secara eksplisit melalui konfigurasi:

```php
// config/security-defense.php
return [
    'epistemic' => [
        'enabled' => false,
    ],
];
```

Nilai `false` adalah default aman. Saat fitur belum diaktifkan, aplikasi jangan menganggap hasil analisis epistemik tersedia. Aktivasi harus dilakukan setelah pengujian, pengamatan beban, dan peninjauan kebijakan.

## Lokasi komponen

Seluruh komponen baru berada di `src/Epistemic` dan dipisahkan dari komponen deteksi lama:

- `DTO/AnalysisContext`: konteks analisis berisi event, bukti tambahan, subjek, dan jendela waktu.
- `DTO/ThreatAssessment`: hasil analisis dengan risk, confidence, hypotheses, evidence, dan decision.
- `Evidence/`: normalisasi serta koleksi bukti.
- `Belief/` dan `Correlation/`: pembentukan hipotesis dari bukti yang saling berkaitan.
- `Engine/`: perhitungan keyakinan dan risiko.
- `Policy/`: keputusan kebijakan berdasarkan assessment.
- `Memory/` dan `Feedback/`: penyimpanan pengalaman serta umpan balik.
- `Graph/`: relasi node/edge ancaman.
- `AI/`: batas provider bukti AI.

## Alur analisis

```text
SecurityEvent / bukti tambahan
          |
          v
EvidenceBuilder + EvidenceCollection
          |
          v
korelasi temporal dan bounded graph traversal
          |
          v
hipotesis ancaman + confidence
          |
          v
risk engine
          |
          v
policy engine -> ThreatAssessment
```

Graph traversal selalu dibatasi oleh konteks analisis dan batas internal traversal. Batas ini mencegah korelasi tanpa ujung, pertumbuhan memori tak terkendali, dan biaya yang tidak proporsional terhadap ukuran telemetry. Sistem menggabungkan bukti dalam jendela waktu `AnalysisContext`; sistem bukan mesin pencari bebas atas seluruh histori.

## Bukti, confidence, risk, policy, memory

### Evidence

Bukti berasal dari `SecurityEvent`, bukti yang diberikan melalui `AnalysisContext`, dan—bila provider dikonfigurasi—bukti dari provider AI. Bukti disanitasi dan dikumpulkan sebelum korelasi. Bukti tidak sama dengan fakta absolut; setiap bukti harus dibaca bersama sumber dan konteksnya.

### Confidence

`confidence` menyatakan seberapa kuat bukti mendukung hipotesis setelah bukti pendukung dan kontradiktif dipertimbangkan. Confidence bukan probabilitas kebenaran yang dijamin dan bukan pengganti verifikasi operasional.

### Risk

`risk` adalah skor risiko hasil `RiskEngine` untuk assessment. Risk membantu pemeringkatan dan pengambilan tindakan, tetapi tidak membuktikan identitas penyerang atau niatnya.

### Policy

`PolicyEngine` mengubah assessment menjadi `ThreatDecision` melalui `decision()`. Policy tetap menjadi otoritas tindakan. AI dan hipotesis tidak boleh langsung memblokir request atau mengubah akses tanpa policy yang eksplisit.

### Memory dan feedback

Memory menyimpan pengalaman pola agar analisis berikutnya dapat belajar dari outcome. Jika belum ada method feedback publik pada manager, gunakan `FeedbackHandler` yang tersedia dan kirim `ThreatBelief` dari `hypotheses()`:

```php
use Mixudev\SecurityDefense\Epistemic\Feedback\FeedbackHandler;
use Mixudev\SecurityDefense\Epistemic\Memory\ExperienceMemory;

$feedback = new FeedbackHandler(app(ExperienceMemory::class));
$hypotheses = $assessment->hypotheses();

if ($hypotheses !== []) {
    $feedback->record($hypotheses[0], 'confirmed');
}
```

Outcome string harus mengikuti vocabulary yang dipakai aplikasi. Contoh `'confirmed'` hanya contoh outcome yang dicatat; jangan menganggap feedback sebagai bukti baru tanpa proses validasi.

## Batas provider AI

`AiEvidenceProviderInterface` hanya memasok evidence tambahan melalui `getEvidenceFor(AnalysisContext $context): array`. Provider default `NullAiProvider` tidak memasok bukti.

AI berada di sisi **evidence source**, bukan decision authority. Provider tidak boleh:

- mengubah `ThreatAssessment` secara langsung;
- melewati `EvidenceCollection`, confidence, risk, atau policy;
- mengeksekusi blocking, quarantine, atau tindakan administratif;
- menerima secret, token, password, atau payload mentah yang belum disanitasi.

Implementasi provider nyata harus didaftarkan melalui binding Service Provider aplikasi. Dokumentasi ini tidak menetapkan vendor, endpoint, format kredensial, retry, atau SLA provider tertentu. Kegagalan provider harus diperlakukan sebagai bukti AI tidak tersedia, bukan sebagai alasan otomatis memblokir request.

## Invariant arsitektur

1. `record()` lama tetap kompatibel dan tidak diganti oleh `analyze()`.
2. `analyze()` hanya digunakan setelah `security-defense.epistemic.enabled` diaktifkan.
3. `AnalysisContext` membatasi event, bukti, subjek, dan waktu yang dianalisis.
4. Graph traversal tetap bounded.
5. Policy memegang keputusan tindakan.
6. AI hanya pemasok bukti.
7. Sanitization dan batas ukuran tetap berlaku pada input yang tidak tepercaya.

## Keterbatasan keamanan

- Analisis dapat menghasilkan false positive dan false negative.
- Event yang hilang, timestamp yang salah, identitas yang dipalsukan, atau telemetry yang terlambat dapat menurunkan confidence.
- Risk dan confidence bukan jaminan keamanan, atribusi, atau bukti forensik.
- Memory dapat memperkuat pola yang salah bila feedback salah atau tidak terverifikasi.
- Provider AI menambah risiko kebocoran data, prompt injection, availability failure, dan biaya; minimalkan data serta gunakan timeout dan kontrol jaringan di integrasi aplikasi.
- Bounded traversal membatasi cakupan analisis. Serangan dengan rantai bukti di luar jendela atau batas traversal dapat tidak terhubung.
- Jangan memakai assessment sebagai satu-satunya dasar tindakan destruktif atau keputusan terhadap pengguna tanpa kontrol policy dan verifikasi tambahan.

## Catatan upgrade

- Upgrade package tidak menghapus pipeline `record()`.
- Pertahankan `epistemic.enabled=false` selama migrasi dan aktifkan bertahap setelah regression test.
- Tinjau binding provider AI, sanitization, retention memory, dan policy setiap upgrade.
- Jangan mengandalkan properti internal komponen `src/Epistemic`; gunakan API publik `AnalysisContext`, `SecurityEvent`, `SecurityDefense::analyze`, accessor `ThreatAssessment`, dan `FeedbackHandler` yang terdokumentasi.
- Jika versi berikutnya mengubah bentuk `ThreatAssessment`, migrasikan pemanggilan accessor secara eksplisit; jangan membaca properti internal sebagai kontrak stabil.
