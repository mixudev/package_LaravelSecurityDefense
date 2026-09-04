# 01 — Instalasi

Panduan instalasi lengkap package `mixudev/security-defense`.

---

## 1. Persyaratan Sistem

- PHP `^8.2`
- Laravel `^10 | ^11 | ^12 | ^13`
- Composer 2.x
- (Opsional, direkomendasikan untuk produksi) Redis atau Memcached sebagai cache driver

---

## 2. Instalasi via Composer

```bash
composer require mixudev/security-defense
```

Package ini memakai **laravel package auto-discovery**, jadi service provider
`Mixudev\SecurityDefense\Providers\SecurityDefenseServiceProvider` terdaftar
otomatis. Anda tidak perlu menambahkannya manual ke `config/app.php`.

> Jika auto-discovery dimatikan di aplikasi (`dont-discover`), daftarkan provider
> manual di `config/app.php` `providers[]`:
> ```php
> Mixudev\SecurityDefense\Providers\SecurityDefenseServiceProvider::class,
> ```

---

## 3. Publish File Package

Publish semua file yang bisa dikustomisasi (config + migration + views):

```bash
php artisan vendor:publish --provider="Mixudev\SecurityDefense\Providers\SecurityDefenseServiceProvider"
```

Atau publish per bagian (lebih fleksibel):

```bash
# Hanya konfigurasi
php artisan vendor:publish --tag=security-defense-config

# Hanya migration
php artisan vendor:publish --tag=security-defense-migrations

# Hanya views (untuk kustomisasi tampilan dashboard)
php artisan vendor:publish --tag=security-defense-views
```

Hasil publish:

| Tag | Tujuan |
|-----|--------|
| `security-defense-config` | `config/security-defense.php` |
| `security-defense-migrations` | `database/migrations/` |
| `security-defense-views` | `resources/views/vendor/security-defense/` |

---

## 4. Jalankan Migration

Migration membuat tabel:

- `security_alerts` — menyimpan alert keamanan
- `security_quarantines` — IP quarantine persisten (dipakai jika
  `SECURITY_QUARANTINE_PERSIST_DB=true`)

```bash
php artisan migrate
```

---

## 5. Verifikasi Instalasi

Cek halaman dashboard (harus via localhost / environment local):

```
http://localhost/security-defense
```

Cek command diagnostic channel tersedia:

```bash
php artisan list | grep security
# security:test-webhook
```

Jika dua hal di atas berfungsi, package sudah terpasang dengan benar.

---

## 6. Variable Environment Minimum

Salin konfigurasi berikut ke `.env` aplikasi Anda:

```env
SECURITY_DEFENSE_ENABLED=true
```

Lanjut ke [02-integration.md](./02-integration.md) untuk menghubungkan package
ke aplikasi Anda.
