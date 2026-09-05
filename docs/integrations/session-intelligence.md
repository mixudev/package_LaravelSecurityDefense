# Integrasi Session Intelligence & Pertahanan Sisi Klien

Modul **Session Intelligence** pada `mixudev/security-defense` bertindak sebagai **lapisan pertahanan terakhir (*last line of defense*)** untuk melindungi akun pengguna dan admin ketika device korban terinfeksi virus/malware (*infostealer*), mengalami pencurian session cookie, atau dieksploitasi oleh bot scraping pasca-autentikasi.

---

## 1. Latar Belakang Ancaman: Korban Terinfeksi Malware

Ketika laptop atau browser user/admin terinfeksi malware (misalnya Trojan Infostealer: RedLine, LummaC2, Vidar):
1. Malware menyalin cookie session aktif (`laravel_session`, `XSRF-TOKEN`) langsung dari disk browser korban.
2. Penyerang melakukan *cookie replay* dari mesin penyerang menggunakan tool otomatis atau Burp Suite.
3. Server Laravel menerima cookie autentik yang sah, sehingga menganggap request tersebut 100% valid.

**Session Intelligence mendeteksi perbedaan karakteristik lingkungan dan pola perilaku sesi tersebut secara proaktif.**

---

## 2. Cara Mengaktifkan Middleware

Daftarkan middleware `AuthenticatedSessionScanner` pada grup route web yang terautentikasi (`auth` middleware).

### Laravel 11, 12, 13 (`bootstrap/app.php`):
```php
use Mixudev\SecurityDefense\Middleware\AuthenticatedSessionScanner;

return Application::configure(basePath: dirname(__DIR__))
    ->withMiddleware(function (Middleware $middleware) {
        // Daftarkan di grup 'web' setelah auth
        $middleware->web(append: [
            AuthenticatedSessionScanner::class,
        ]);
    })
    ->create();
```

### Laravel 10 (`app/Http/Kernel.php`):
```php
protected $middlewareGroups = [
    'web' => [
        // ... middleware bawaan
        \Illuminate\Auth\Middleware\Authenticate::class,
        \Mixudev\SecurityDefense\Middleware\AuthenticatedSessionScanner::class,
    ],
];
```

---

## 3. Tiga Aturan Deteksi Sesi Baru

### A. Deteksi Pembajakan Sesi (`SessionFingerprintRule`)
- **Tujuan**: Mendeteksi jika session cookie yang sama tiba-tiba digunakan dari lingkungan jaringan atau klien yang kontradiktif.
- **Mekanisme**:
  - Saat request pertama sesi masuk, sistem mencatat baseline IP subnet (`/24` IPv4 atau `/48` IPv6 untuk mentolerir rotasi DHCP normal) dan hash User-Agent ke dalam cache.
  - Jika request berikutnya pada sesi yang sama datang dari subnet yang jauh berbeda ATAU User-Agent berubah drastis (misal dari Chrome Windows ke `curl` atau Python `requests`), sistem langsung menerbitkan alert:
    ```
    Threat Type: session_hijack_suspected
    Severity: critical
    Mismatches: ['user_agent_drift', 'network_subnet_drift']
    ```

### B. Deteksi Kecepatan Aksi Tidak Manusiawi (`BehavioralVelocityRule`)
- **Tujuan**: Mendeteksi scraper bot atau skrip otomatis yang mengeksploitasi akun terautentikasi untuk mencuri data secara massal.
- **Mekanisme**:
  - Menghitung RPM (*Requests Per Minute*) per user ID terautentikasi menggunakan atomic sliding-window counter.
  - Jika RPM melebihi ambang batas wajar interaksi manusia (default: > 120 RPM), sistem mentrigger alert `suspicious_velocity_scraping`.

### C. Deteksi Inkonsistensi Header Klien (`HttpHeaderConsistencyRule`)
- **Tujuan**: Mendeteksi tool otomatis atau headless browser yang memalsukan User-Agent browser asli namun gagal mereplikasi header HTTP secara utuh.
- **Mekanisme**:
  - Mengidentifikasi request yang mengaku `Mozilla/Chrome` tetapi tidak mengirimkan header standar browser seperti `Accept-Language`, `Accept-Encoding`, atau `Sec-Fetch-*`.

---

## 4. Konfigurasi `config/security-defense.php`

```php
'session_intelligence' => [
    'enabled' => true,
    
    // Set ke true jika ingin request langsung di-abort 403 saat terjadi pembajakan sesi kritis
    'block_on_hijack' => false,
],

'detection' => [
    'rules' => [
        'session_fingerprint' => [
            'enabled' => true,
            'severity' => 'high',
            'session_ttl' => 7200, // 2 jam cache window
        ],

        'behavioral_velocity' => [
            'enabled' => true,
            'threshold' => 120,    // Maksimal 120 request per menit per user
            'window' => 60,        // Detik
            'severity' => 'high',
        ],

        'header_consistency' => [
            'enabled' => true,
            'severity' => 'medium',
        ],
    ],
],
```

---

## 5. Pemantauan di Dashboard

Kunjungi URL `/security-defense/sessions`:
- **Kartu Metrik**: Menampilkan total ancaman sesi, kecurigaan pembajakan sesi (*hijack*), lonjakan *velocity*, dan anomali header.
- **Tabel Telemetri Sesi**: Memeriksa detail bukti anomali (subnet drift, UA mismatch, jumlah request per window) serta tombol tindakan cepat (*Acknowledge* & *Resolve*).
