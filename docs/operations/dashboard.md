# Dashboard SIEM & Monitoring

Package menyediakan dashboard pemantauan keamanan lokal (*local SIEM*) berbasis web yang dapat langsung diakses dari browser.

---

## 1. Rute & Konfigurasi Akses

URL default dashboard:
```
http://localhost/security-defense
```

Pengaturan di `config/security-defense.php` (`dashboard`):
- `enabled`: Mengaktifkan rute dashboard (default `true`).
- `path`: URL slug path (default `'security-defense'`).
- `local_only`: Batasi akses hanya untuk localhost / environment `local` (default `true`).

---

## 2. Pengamanan Akses di Server Produksi (`EnsureLocalAccess`)

Dashboard dilindungi oleh middleware khusus `EnsureLocalAccess`. Pada environment produksi, akses akan ditolak (HTTP 403) kecuali jika:
1. Alamat IP terdaftar pada `config('security-defense.dashboard.allowed_ips')`.
2. Anda mendefinisikan Laravel Gate bernama `viewSecurityDefenseDashboard` di `AppServiceProvider::boot()`:

```php
use Illuminate\Support\Facades\Gate;

Gate::define('viewSecurityDefenseDashboard', function ($user) {
    return $user !== null && $user->is_admin === true;
});
```

Dengan Gate ini, hanya administrator terautentikasi yang dapat membuka halaman dashboard di server live.

---

## 3. Fitur Utama & Navigasi Multi-Tab

Dashboard dilengkapi sistem navigasi tab responsif di bagian navbar atas untuk berpindah antar modul monitoring:

### Tab 1: Threat Telemetry SIEM (`/security-defense`)
- **Kartu Ringkasan Metrik**: Menampilkan Total Ancaman, IP Terkarantina, Alert Belum Ditinjau, dan Insiden Kritis.
- **Distribusi Vektor Ancaman**: Progress bar proporsional persentase jenis serangan.
- **Hub Saluran Notifikasi**: Indikator status Database, Telegram, Discord, Webhook, dan Mail beserta tombol *Test Probe* instan.
- **Tabel Karantina IP**: Memantau IP yang sedang diblokir beserta tombol pembebasan (*pardon*).
- **Log Security Alerts**: Tabel insiden yang dapat difilter berdasarkan status (new/resolved) dan severity, lengkap dengan modal inspeksi telemetri.

### Tab 2: Database Mutations & Tamper Audit (`/security-defense/data-audits`)
- **Indikator BURP TAMPER DETECTED**: Label merah berkedip untuk mutasi data yang terindikasi manipulasi parameter via proxy (Burp Suite/ZAP) atau Mass Assignment.
- **Side-by-Side Diff Inspector**: Modal interaktif yang menampilkan perbandingan nilai lama (*old values*) vs nilai baru (*new values*) dengan highlight warna dan penyensoran data sensitif.
- **Request Payload Inspector**: Menampilkan snapshot JSON body request asli saat data diubah.
- **Filter Cepat**: Berdasarkan event (created, updated, deleted), model class, tamper status, dan kata kunci IP/URL/Actor.

### Tab 3: Session Intelligence Telemetry (`/security-defense/sessions`)
- **Pemantauan Risiko Sesi Klien**: Menampilkan log anomali post-authentication seperti kecurigaan pembajakan sesi akibat malware infostealer (*subnet drift* & *UA mismatch*), lonjakan kecepatan bot (*velocity spikes*), serta inkonsistensi header browser.
- **Tindakan Cepat**: Acknowledge dan Resolve langsung dari tampilan tabel.

---

## 4. Sistem Tema Dark & Light

- Dibangun menggunakan JavaScript murni (vanilla JS) tanpa dependensi Alpine.js.
- Menyimpan preferensi pengguna di `localStorage` dengan sinkronisasi otomatis ke setting mode gelap OS browser.
- Memanfaatkan fitur `@custom-variant dark (&:where(.dark, .dark *))` pada Tailwind CSS browser runtime.
