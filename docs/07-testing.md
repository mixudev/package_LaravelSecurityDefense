# 07 — Testing & Diagnostic

Cara menjalankan test suite package dan melakukan diagnostic channel.

---

## 1. Menjalankan Test Suite Package

Di root package (development):

```bash
composer test
```

Atau langsung via PHPUnit:

```bash
./vendor/bin/phpunit
```

Contoh output:

```text
PHPUnit 11.5.56 by Sebastian Bergmann and contributors.

......................................................... 68 / 68 (100%)
Time: 00:04.038, Memory: 52.00 MB

OK (68 tests, 260 assertions)
```

Suite mencakup:

- Unit test detection rules (brute force, credential stuffing, distributed
  spray, payload injection, impossible travel, path recon, rate limit bypass,
  user agent anomaly)
- Anti-ReDoS & anti-memory exhaustion bounds
- IP quarantine (jail / pardon / whitelist)
- Alert deduplication & rate limiter
- Alert dispatcher & channel delivery
- Dashboard access (local-only, CSRF, gate) & render dengan data
- Email alert (`MailChannel`)

---

## 2. Diagnostic Channel via Artisan

Test konektivitas channel alert dan webhook:

```bash
# Semua channel
php artisan security:test-webhook --all

# Satu channel spesifik
php artisan security:test-webhook telegram
php artisan security:test-webhook discord
php artisan security:test-webhook webhook
php artisan security:test-webhook mail
```

Output tabel:

```text
+----------+---------+-------------+----------+---------+----------------------+
| Channel  | Enabled | Configured  | Delivery | Latency | Diagnostic Message    |
+----------+---------+-------------+----------+---------+----------------------+
| DATABASE | YES     | YES         | SUCCESS  | -       | DB alert created      |
| TELEGRAM | YES     | YES         | SUCCESS  | 320 ms  | Message sent          |
| ...      | ...     | ...         | ...      | ...     | ...                   |
+----------+---------+-------------+----------+---------+----------------------+
```

Kode keluar: `0` = sukses, `1` = gagal (berguna untuk CI).

---

## 3. Test Channel via Dashboard UI

Buka dashboard (`/security-defense`) dan klik **Test Probe** pada kartu channel.
Endpoint `POST /test-channel` dibatasi rate-limit (10/menit/IP) dan wajib CSRF.

---

## 4. Menulis Test Kustom di Aplikasi Anda

Cukup gunakan facade/manager yang sama seperti di produksi:

```php
// tests/Feature/SecurityDefenseIntegrationTest.php
public function test_failed_login_records_brute_force_threat(): void
{
    $this->withoutMiddleware();

    for ($i = 0; $i < 11; $i++) {
        SecurityDefense::record([
            'ip' => '198.51.100.9',
            'identifier' => 'bob@example.com',
            'eventType' => 'LoginFailed',
            'userAgent' => 'Mozilla/5.0',
        ]);
    }

    $this->assertTrue(SecurityDefense::quarantine()->isQuarantined('198.51.100.9'));
}
```

Lanjut ke [08-troubleshooting.md](./08-troubleshooting.md).
