# 03 — Konfigurasi Channel Alert

Package mendukung 5 channel notifikasi keamanan yang dapat diaktifkan terpisah:
Database, Telegram, Discord, Webhook/SIEM, dan Email (native Laravel Mail).

Semua konfigurasi via environment variable (`.env`) atau `config/security-defense.php`.

---

## Channel yang Tersedia

| Channel | Env Master | Deskripsi |
|---------|-----------|-----------|
| Database | selalu aktif | Menyimpan alert ke tabel `security_alerts` (wajib) |
| Telegram | `SECURITY_TELEGRAM_ENABLED` | Kirim alert ke chat Telegram |
| Discord | `SECURITY_DISCORD_ENABLED` | Kirim alert ke webhook Discord |
| Webhook/SIEM | `SECURITY_WEBHOOK_ENABLED` | Kirim ke endpoint eksternal (ditandatangani HMAC-SHA256) |
| Email | `SECURITY_MAIL_ENABLED` | Kirim via Laravel Mail (SMTP/SES/Resend/Mailgun) |

---

## 1. Database Channel

Selalu aktif, tidak perlu konfigurasi. Menyimpan alert ke tabel `security_alerts`.
Opsional ganti nama tabel:

```env
SECURITY_DEFENSE_TABLE=custom_security_alerts
```

> Pastikan nama tabel custom sudah dibuat migration-nya terlebih dahulu.

---

## 2. Master Toggle & Queue

```env
# Master toggle seluruh package
SECURITY_DEFENSE_ENABLED=true

# Background queue (offload notifikasi ke worker -> zero request latency)
SECURITY_DEFENSE_QUEUE_ENABLED=true
SECURITY_DEFENSE_QUEUE_CONNECTION=redis
SECURITY_DEFENSE_QUEUE_NAME=security-alerts
```

Saat queue aktif (dan worker jalan:

```bash
php artisan queue:work --queue=security-alerts
```

notifikasi Telegram/Discord/Webhook/Email dikirim asynchronous.

> Jika `SECURITY_DEFENSE_QUEUE_ENABLED=false`, notifikasi dikirim **sinkron**
> (menambah sedikit latency request).

---

## 3. Telegram

```env
SECURITY_TELEGRAM_ENABLED=true
SECURITY_TELEGRAM_BOT_TOKEN=123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ
SECURITY_TELEGRAM_CHAT_ID=-1001234567890
```

- `bot_token`: token bot dari @BotFather
- `chat_id`: ID chat/grup tujuan (bisa negatif untuk grup / channel)

> **Fitur Interactive Control Panel & Monitoring Bot:**
> Selain notifikasi satu arah, bot juga mendukung menu interaktif untuk health check website, metrik keamanan, log insiden, dan karantina IP. Panduan lengkap arsitektur Webhook (produksi) vs Long-Polling (lokal) tersedia di [09-telegram-bot.md](./09-telegram-bot.md).

---

## 4. Discord

```env
SECURITY_DISCORD_ENABLED=true
SECURITY_DISCORD_WEBHOOK=https://discord.com/api/webhooks/123456789/token_here
```

Buat webhook di Discord: Server Settings > Integrations > Webhooks.

---

## 5. Webhook / SIEM

```env
SECURITY_WEBHOOK_ENABLED=false
SECURITY_WEBHOOK_URL=https://siem.example.com/api/v1/alerts
SECURITY_WEBHOOK_SECRET=your-hmac-sha256-signing-secret
```

Setiap payload dikirim dengan header `X-Signature: sha256=<HMAC>`
(menggunakan `secret` sebagai kunci). Penerima harus memverifikasi signature
untuk memastikan payload memang dari aplikasi Anda.

Contoh verifikasi di penerima (Node.js):

```js
const crypto = require('crypto');
const sig = crypto
  .createHmac('sha256', process.env.WEBHOOK_SECRET)
  .update(JSON.stringify(body))
  .digest('hex');
if (req.headers['x-signature'] !== `sha256=${sig}`) {
  return res.status(401).json({ error: 'invalid signature' });
}
```

---

## 6. Email (Native Laravel Mail)

Gunakan driver mail standar Laravel (SMTP/SES/Resend/Mailgun). Pastikan
`MAIL_*` di `.env` sudah terisi benar.

```env
# --- Konfigurasi mail Laravel standar ---
MAIL_MAILER=smtp
MAIL_HOST=smtp.example.com
MAIL_PORT=587
MAIL_USERNAME=...
MAIL_PASSWORD=...
MAIL_ENCRYPTION=tls
MAIL_FROM_ADDRESS=security@example.com
MAIL_FROM_NAME="Security Defense"

# --- Security Defense email alert ---
SECURITY_MAIL_ENABLED=true
SECURITY_ALERT_EMAIL=admin@example.com          # satu alamat, atau array JSON
# SECURITY_ALERT_EMAIL=["admin@example.com","ops@example.com"]
SECURITY_MAIL_SUBJECT_PREFIX=[SECURITY DEFENSE ALERT]
```

Template email dapat dipublikasikan dan dikustomisasi (lihat [04-dashboard.md](./04-dashboard.md)).

---

## 7. Menguji Channel (Diagnostic)

### Via Artisan CLI

```bash
# Test semua channel
php artisan security:test-webhook --all

# Test satu channel
php artisan security:test-webhook telegram
php artisan security:test-webhook mail
php artisan security:test-webhook webhook
php artisan security:test-webhook discord
```

Output berupa tabel: Channel, Enabled, Configured, Delivery, Latency, Message.

### Via Dashboard

Buka dashboard SIEM (lihat [04-dashboard.md](./04-dashboard.md)) dan klik
tombol **Test Probe** pada kartu channel yang ingin diuji.

Endpoint `POST /security-defense/test-channel` dibatasi rate-limit (10/menit/IP)
dan wajib CSRF.

---

## 8. Ringkasan `.env` Lengkap Alert

```env
# Master
SECURITY_DEFENSE_ENABLED=true

# Queue
SECURITY_DEFENSE_QUEUE_ENABLED=true
SECURITY_DEFENSE_QUEUE_CONNECTION=redis
SECURITY_DEFENSE_QUEUE_NAME=security-alerts

# Telegram
SECURITY_TELEGRAM_ENABLED=true
SECURITY_TELEGRAM_BOT_TOKEN=...
SECURITY_TELEGRAM_CHAT_ID=...

# Discord
SECURITY_DISCORD_ENABLED=true
SECURITY_DISCORD_WEBHOOK=...

# Webhook SIEM
SECURITY_WEBHOOK_ENABLED=false
SECURITY_WEBHOOK_URL=...
SECURITY_WEBHOOK_SECRET=...

# Email
SECURITY_MAIL_ENABLED=true
SECURITY_ALERT_EMAIL=admin@example.com
```

Lanjut ke [04-dashboard.md](./04-dashboard.md).
