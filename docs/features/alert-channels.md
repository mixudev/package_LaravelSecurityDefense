# Notifikasi Multi-Channel & Deduplikasi Alert

Package mendistribusikan laporan ancaman keamanan ke 5 saluran notifikasi dengan dukungan perlindungan deduplikasi dan rate-limiting.

---

## Ringkasan Channel Notifikasi

| Channel | Pengaturan Config | Media Pengiriman | Mekanisme Fallback |
|---|---|---|---|
| Database | Selalu aktif | Tabel database via Eloquent (`SecurityAlert`) | Saluran wajib utama |
| Telegram | `telegram.enabled` | Telegram Bot API (Markdown & teks terstruktur) | Log error aman tanpa crash |
| Discord | `discord.enabled` | Webhook API Discord (Embed warna severity) | Log error aman tanpa crash |
| Webhook / SIEM | `webhook.enabled` | HTTP POST dengan tanda tangan HMAC-SHA256 | Log error aman tanpa crash |
| Email | `mail.enabled` | Laravel Mail (`SecurityAlertMail`) | Log error aman tanpa crash |

---

## 1. Deduplikasi Alert (Anti-Spam)

Untuk mencegah badai ribuan pesan saat diserang terus-menerus, `AlertDeduplicator` menghitung fingerprint unik SHA-256:

```text
fingerprint = sha256(threatType + targetIdentifier + ruleIdentifier)
```

Dalam batas jendela deduplikasi (default 300 detik / 5 menit), ancaman berulang dengan fingerprint identik tidak akan dikirim ulang ke chat Telegram/Discord/Webhook, menjaga kuota rate-limit API pihak ketiga tetap aman.

---

## 2. Pengiriman Asinkron via Antrean (Queue)

Untuk menjamin waktu respons HTTP pengguna tidak terganggu oleh latensi request keluar ke Telegram atau Discord, aktifkan fitur queue pada `config/security-defense.php`:

```php
'queue' => [
    'enabled' => true,
    'connection' => 'redis',
    'queue_name' => 'security-alerts',
],
```

Jalankan worker queue di background:

```bash
php artisan queue:work --queue=security-alerts
```

---

## 3. Format Webhook & Verifikasi Tanda Tangan HMAC

Setiap pengiriman webhook ke SIEM eksternal dilengkapi header HTTP:
`X-Security-Defense-Signature: sha256=<hmac_hex>`

Contoh verifikasi payload di sisi server penerima:

```php
$signature = $request->header('X-Security-Defense-Signature');
$expected = 'sha256=' . hash_hmac('sha256', $request->getContent(), config('services.siem.secret'));

if (! hash_equals($expected, (string) $signature)) {
    abort(401, 'Tanda tangan webhook tidak valid');
}
```
