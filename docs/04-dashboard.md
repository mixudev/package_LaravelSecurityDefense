# 04 — Dashboard SIEM (Monitoring & Tema)

Dashboard lokal untuk memantau postur keamanan: statistik threat, distribusi
vektor serangan, IP quarantine, daftar alert, dan diagnostic test channel.

---

## 1. Akses Dashboard

Router dashboard otomatis terdaftar oleh service provider (jika diaktifkan).

```
http://localhost/security-defense
```

### Konfigurasi Akses (`.env` / config)

```env
# Aktif/nonaktif dashboard
SECURITY_DEFENSE_DASHBOARD_ENABLED=true

# Ubah path (mis. /monitor)
SECURITY_DEFENSE_DASHBOARD_PATH=security-defense

# Hanya akses local (true = aman default)
SECURITY_DEFENSE_DASHBOARD_LOCAL_ONLY=true
```

### Akses & Keamanan (EnsureLocalAccess)

`/security-defense` dilindungi oleh middleware `EnsureLocalAccess`:

- **`local_only=true` (default)**: hanya bisa diakses jika
  `app()->environment() === 'local'` ATAU IP request ada di `allowed_ips`.
- **`allowed_ips`** (config `security-defense.dashboard.allowed_ips`):
  daftar IP yang diizinkan masuk walau environment production:
  ```php
  'allowed_ips' => ['127.0.0.1', '::1', '203.0.113.10'],
  ```
- **Gate kustom** (opsional, paling aman): definisikan Gate
  `viewSecurityDefenseDashboard`. Jika gate ini ada dan mengembalikan `true`,
  akses diizinkan. Ini cara yang benar untuk membuka dashboard di production
  dengan auth aplikasi:
  ```php
  // AppServiceProvider::boot()
  Gate::define('viewSecurityDefenseDashboard', function ($user) {
      return $user->is_admin; // hanya admin
  });
  ```

> Tidak ada mekanisme login bawaan dashboard. **Jangan** set `local_only=false`
> tanpa Gate kustom di production.

---

## 2. Fitur Dashboard

- Kartu statistik (Total Threats, Quarantined IPs, New Alerts, Critical)
- Distribusi vektor serangan (progress bar proporsional + persentase)
- Grid 5 channel alert dengan tombol **Test Probe** (CSRF + rate-limit)
- Tabel **IP Quarantines** dengan aksi Release (pardon)
- Tabel **Security Alerts** dengan filter status & severity, tombol
  Acknowledge / Resolve / Inspect (telemetry modal)
- Banner status engine & toggle tema

---

## 3. Tema (Dark / Light Mode)

Dashboard punya toggle **Dark / Light** di navbar kanan.

### Cara kerja tema

- Implementasi **murni vanilla JavaScript** (TIDAK butuh Alpine.js / CDN lain).
- Toggle membolak-balik class `dark` pada elemen `<html>`.
- Preferensi disimpan ke `localStorage` (`security_defense_theme`) dan
  memperhatikan `prefers-color-scheme` saat load pertama (anti-flash).

### Jika toggle "tidak berfungsi" (gaya tidak berubah)

Tailwind v4 browser runtime secara **default** mematikan varian `dark:` ke
`prefers-color-scheme` (media query OS), BUKAN class. Agar class `.dark` yang
di-toggle bekerja, layout sudah menyertakan deklarasi:

```html
<style type="text/tailwindcss">
    @custom-variant dark (&:where(.dark, .dark *));
</style>
```

- Jika Anda **mem-publish views** untuk kustomisasi dan menghapus blok ini,
  toggle akan berhenti mengubah gaya. **Pastikan blok `<style type="text/tailwindcss">`
  dengan `@custom-variant dark (...)` tetap ada** di `layouts/app.blade.php`.

- Alpinetidak diperlukan. Jangan tambahkan Alpine CDN untuk fungsi ini.

---

## 4. Kustomisasi Tampilan (Publish Views)

Untuk mengubah tampilan dashboard, publish views dulu:

```bash
php artisan vendor:publish --tag=security-defense-views
```

File ter-publish di `resources/views/vendor/security-defense/`:

```text
resources/views/vendor/security-defense/
├── layouts/app.blade.php
├── dashboard.blade.php
├── components/
│   ├── navbar.blade.php
│   ├── alert-banner.blade.php
│   ├── alerts-table.blade.php
│   ├── channel-card.blade.php
│   ├── channels-hub.blade.php
│   ├── quarantine-table.blade.php
│   ├── stat-card.blade.php
│   ├── telemetry-modal.blade.php
│   └── threat-distribution.blade.php
└── emails/alert.blade.php
```

Edit bebas sesuai kebutuhan (struktur Tailwind v4 + Inter/JetBrains Mono).

> **Catatan styling:**
> - Tema memakai **Tailwind v4 via CDN browser runtime** (`@tailwindcss/browser@4`),
>   cocok untuk dashboard local-only tanpa build step.
> - Jika dashboard ingin diexpose non-local (dengan Gate kustom), pertimbangkan
>   mengganti ke **Tailwind compiled** (Vite) untuk purge & CSP. Lihat
>   [06-security-hardening.md](./06-security-hardening.md).
> - Ikon pakai **SVG inline** (bukan emoji) sesuai standar tampilan dashboard.

---

## 5. Endpoint Dashboard

| Method | URI | Nama Rute | Fungsi |
|--------|-----|-----------|--------|
| GET | `/security-defense` | `security-defense.dashboard` | Tampilkan dashboard |
| POST | `/security-defense/test-channel` | `security-defense.test-channel` | Test channel (rate-limited, CSRF) |
| POST | `/security-defense/alerts/{alert}/acknowledge` | `security-defense.alerts.acknowledge` | Acknowledge alert |
| POST | `/security-defense/alerts/{alert}/resolve` | `security-defense.alerts.resolve` | Resolve alert |
| POST | `/security-defense/quarantine/pardon` | `security-defense.quarantine.pardon` | Lepas IP dari quarantine |

Semua endpoint `POST` wajib CSRF token.

Semua nama rute berprefiks `security-defense.` sehingga mudah dipakai
(`route('security-defense.dashboard')`).

Lanjut ke [05-customization.md](./05-customization.md).
