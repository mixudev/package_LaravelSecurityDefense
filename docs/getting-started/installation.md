# Instalasi

Panduan instalasi dan konfigurasi dasar package `mixudev/security-defense`.

---

## Persyaratan Sistem

- PHP `^8.2`
- Laravel `10.x`, `11.x`, `12.x`, atau `13.x`
- Composer 2.x
- Cache store yang disarankan: **Redis** atau **Memcached** (driver file/array akan kehilangan state sliding window dan karantina saat restart).

---

## 1. Instalasi via Composer

Jalankan perintah berikut di root proyek Laravel:

```bash
composer require mixudev/security-defense
```

Package mendukung auto-discovery Laravel. Service provider dan Facade akan didaftarkan otomatis.

### Setup satu perintah

Untuk instalasi/update idempotent, publish config, setup migrasi, dan setup dashboard opaque:

```bash
php artisan security-defense:install --with-opaque-path
```

Perintah ini:
- menjaga config yang sudah dipublish; gunakan `--force` hanya untuk overwrite config;
- membuat `SECURITY_DEFENSE_DASHBOARD_PATH` dengan 32 random bytes (base64url 43 karakter) jika belum ada;
- menyimpan token hanya di `.env`, tidak menampilkan token, dan tidak menulis token ke config overrides;
- mengaktifkan `dashboard.opaque_path.enabled` tanpa mengubah autentikasi/Gate;
- menjalankan migrasi dan rebuild route cache;
- tidak menjalankan `config:cache` saat opaque path aktif karena secret dibaca runtime.

Opsi:
```text
--force             overwrite published config
--with-opaque-path  enable opaque dashboard path and generate token if absent
--token=VALUE       use supplied 43-88 character base64url token
--no-migrate        skip migrations
--no-cache          skip cache clear/rebuild
--dry-run           show action without changing files
```

Update package:
```bash
composer update mixudev/security-defense --with-dependencies --no-interaction
php artisan security-defense:install --with-opaque-path
```

Package source changed locally but Composer uses a path repository? Run `composer dump-autoload`, then the Artisan command.

---

## 2. Publish File Konfigurasi, Migrasi, dan Views

Manual setup tetap tersedia bila deployment memisahkan tahap publish dan migrate.

Jalankan perintah publish aset:

```bash
# Publish semua aset sekaligus
php artisan vendor:publish --provider="Mixudev\SecurityDefense\Providers\SecurityDefenseServiceProvider"

# Atau publish spesifik konfigurasi saja
php artisan vendor:publish --tag=security-defense-config

# Atau publish migrasi database saja
php artisan vendor:publish --tag=security-defense-migrations

# Atau publish views dashboard/email saja
php artisan vendor:publish --tag=security-defense-views
```

---

## 3. Jalankan Migrasi Database

Jalankan migrasi untuk membuat tabel yang dibutuhkan:

```bash
php artisan migrate
```

Tabel yang dibuat:
1. `security_alerts`: Menyimpan catatan insiden keamanan, tingkat keparahan, fingerprint, status resolusi, dan metadata telemetri yang telah disanitasi.
2. `security_quarantines`: Tabel opsional untuk menyimpan status karantina IP yang persisten (aktif jika opsi `persist_to_database` bernilai `true` pada config).

---

## 4. Pengaturan Kredensial Environment (`.env`)

Sesuai arsitektur package, pengaturan switch enable/disable utama berada di file `config/security-defense.php`. File `.env` hanya digunakan untuk menyimpan kredensial pihak ketiga:

```env
# Kredensial Telegram Bot Alerting
SECURITY_TELEGRAM_BOT_TOKEN=[REDACTED]
SECURITY_TELEGRAM_CHAT_ID=[REDACTED]

# Kredensial Discord Webhook
SECURITY_DISCORD_WEBHOOK=[REDACTED]

# Kredensial Webhook Eksternal / SIEM
SECURITY_WEBHOOK_URL=[REDACTED]
SECURITY_WEBHOOK_SECRET=[REDACTED]

# Email Alert
SECURITY_ALERT_EMAIL=[REDACTED]
```

---

## 5. Verifikasi Instalasi

Jalankan uji diagnostik konektivitas channel melalui Artisan CLI:

```bash
php artisan security:test-webhook --all
```

Langkah berikutnya: Lihat panduan [Quickstart](./quickstart.md) untuk menyambungkan WAF dan event telemetri.
