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
- `allowed_ips`: Daftar alamat IP (atau CIDR) yang diizinkan pada mode lokal (default `['127.0.0.1', '::1']`).
- `public.enabled`: Aktifkan exposure publik secara eksplisit (default `false` — fail-closed).
- `public.allowed_ips` / `public.allowed_cidrs`: Allowlist ketat untuk mode publik.
- `public.authorization_gate`: Nama Laravel Gate yang wajib diizinkan pada mode publik.
- `public.require_authenticated_user`: Wajibkan user terautentikasi (default `true`).
- `public.require_step_up` / `public.step_up_gate`: Verifikasi lanjutan opsional.
- `public.rate_limit`: Batas percobaan akses gagal per IP (default `max_attempts=10` / `decay_seconds=60`).
- `opaque_path.enabled`: Sembunyikan prefix default dan gunakan path opaque host-managed (default `false`). Ini hanya discovery barrier, bukan autentikasi.
- `SECURITY_DEFENSE_DASHBOARD_PATH`: Secret host environment berupa 43+ karakter base64url tanpa `/`, `=`, atau query token. Jangan simpan di config overrides, source, log, atau URL query.

Opaque path memakai static secret dari environment agar kompatibel dengan `route:cache`. Rotasi berarti ubah secret pada deployment, rebuild config/route cache, lalu revoke session host bila ada indikasi kebocoran. Cache-backed atau per-request rotation tidak dipakai: bisa membuat node berbeda, route cache stale, dan open tab mati mendadak.

URL opaque tetap bearer capability sampai secret dirotasi. TLS/HTTPS, secure session cookie, host authentication, Gate, IP/CIDR, CSRF, dan step-up tetap wajib.

Uji production-like di playground/host staging:
```bash
APP_ENV=production APP_DEBUG=false php artisan optimize:clear
php artisan route:list --path=security-defense
php artisan security-defense:install --with-opaque-path --no-migrate
```

Verifikasi URL lama `/security-defense` menghasilkan 404, token opaque valid masuk ke gateway, token salah menghasilkan 404 generic, user tanpa Gate/IP/auth ditolak, dan token tidak muncul pada output command maupun telemetry. Jangan uji public mode tanpa HTTPS dan Gate host.

Akses mode lokal (default, `local_only=true`):
- Hanya environment `local` + alamat IP loopback/allowlist yang bisa masuk.
- Tidak ada login diminta — dashboard adalah alat operasional lokal.
- Gate host tidak pernah bisa meng-elevasi ip non-loopback pada mode lokal.

Akses mode publik (opt-in, `local_only=false`):
- Wajib `public.enabled=true`, jika tidak: HTTP 403.
- Wajib IP/CIDR klien terdaftar di allowlist.
- Wajib user terautentikasi secara host.
- Wajib Gate `public.authorization_gate` mengizinkan (user + request).
- Opsional step-up Gate bila `require_step_up=true`.
- Semua penolakan akses publik dibatasi rate (HTTP 429 setelah batas).

Header keamanan pada semua response dashboard:
`Cache-Control: no-store, no-cache, must-revalidate, private`, `Pragma: no-cache`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`.

Header spoofing tidak pernah dipercaya: `X-Forwarded-For`, `X-Real-IP`, `Client-IP` tidak mempengaruhi keputusan izin.

---

## 2. Pengamanan Akses di Server Produksi (`EnsureLocalAccess`)

Dashboard dilindungi oleh middleware `EnsureLocalAccess`. Kebijakannya fail-closed:

Mode lokal (default `local_only=true`):
1. Environment harus `local`.
2. IP klien harus dalam `allowed_ips` (loopback default — dukungan CIDR).

Jika keduanya tidak terpenuhi: HTTP 403. Gate host tidak relevan di mode ini.

Mode publik (`local_only=false` — hanya untuk deployment yang benar-benar ingin expose; lebih disarankan VPN/private network):
1. `public.enabled` harus `true`.
2. IP klien harus dalam `public.allowed_ips` / `public.allowed_cidrs` (IPv4 dan IPv6, CIDR didukung).
3. Wajib ada user terautentikasi (`require_authenticated_user=true`).
4. Gate `public.authorization_gate` harus diizinkan:

```php
use Illuminate\Support\Facades\Gate;

Gate::define('viewSecurityDefenseDashboard', function ($user) {
    return $user !== null && $user->is_admin === true;
});
```

5. Opsional: step-up Gate kedua bila `require_step_up=true`.

Dengan konfigurasi ini, hanya operator terautentikasi dari alamat IP yang terdaftar yang bisa membuka dashboard saat terpapar publik. Semua kondisi gagal menghasilkan 403/429 yang identik (tanpa bocor alasan/topologi).

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
