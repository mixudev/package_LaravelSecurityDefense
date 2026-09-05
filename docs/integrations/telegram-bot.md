# Bot Telegram Interaktif & Monitoring

Package `mixudev/security-defense` dilengkapi dengan sistem **Interactive Telegram Bot Control Panel**. Bot ini tidak hanya mengirimkan notifikasi saat ancaman terdeteksi, tetapi juga menyediakan dashboard interaktif melalui Telegram untuk memantau kesehatan server, metrik keamanan, log insiden, dan status karantina IP.

---

## 1. Fitur Utama

- **Antarmuka Monospace Bersih**: Format teks rapi berbasis monospace dan bracket status (`[OK]`, `[FAIL]`, `[CRITICAL]`, `•`) tanpa emoji berlebihan.
- **Menu Tombol Inline**: Navigasi interaktif yang memperbarui pesan langsung di tempat (*in-place edit*) tanpa mengotori ruang obrolan.
- **Dukungan Tombol Menu Bawaan**: Pendaftaran otomatis ke Telegram API (`setMyCommands`) agar tombol menu biru muncul di pojok kiri bawah aplikasi Telegram pengguna.
- **Otorisasi Ketat**: Hanya Chat ID terdaftar (`SECURITY_TELEGRAM_CHAT_ID`) yang dapat mengakses data diagnostik sistem.

---

## 2. Arsitektur: Webhook vs Long-Polling

| Karakteristik | Mode Webhook (Produksi / Hosting) | Mode Polling (Localhost / Laptop) |
|---|---|---|
| **Target Environment** | Shared Hosting (cPanel), VPS, Cloud, Server Produksi | Laptop Developer (`127.0.0.1` / Localhost) |
| **Kebutuhan Worker/Daemon** | **TIDAK PERLU** worker sama sekali | Perlu process berjalan di terminal |
| **Beban RAM Server** | **0 MB** (hanya berjalan saat ada request masuk) | Menjalankan proses PHP di CLI |
| **Mekanisme** | Telegram yang "mengetuk" URL website via HTTP POST | Aplikasi yang secara berkala menanyakan data ke Telegram |
| **Command Setup** | `php artisan security:telegram-webhook set` | `php artisan security:telegram-poll` |

---

## 3. Setup di Server Produksi (Mode Webhook)

Di server produksi atau shared hosting cPanel yang memiliki domain HTTPS:

### Langkah 1: Kredensial di `.env`
```env
SECURITY_TELEGRAM_BOT_TOKEN=123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ
SECURITY_TELEGRAM_CHAT_ID=-1001234567890
```

### Langkah 2: Daftarkan Webhook Sekali Saja
Jalankan perintah ini melalui terminal / SSH di server:
```bash
php artisan security:telegram-webhook set
```
Command ini otomatis mendaftarkan URL webhook dan token rahasia enkripsi ke Telegram.

---

## 4. Setup di Localhost / Laptop (Mode Long-Polling)

Jalankan perintah polling di terminal selama development:

```bash
php artisan security:telegram-poll
```

Buka bot di aplikasi Telegram dan kirim perintah `/start` untuk membuka menu interaktif.

---

## 5. Menu & Perintah Interaktif

- `/health`: Memeriksa status database, ketersediaan cache driver, penggunaan RAM, dan uptime.
- `/metrics`: Menampilkan total ancaman, IP aktif di karantina, dan 5 vektor serangan teratas.
- `/incidents`: Melihat daftar insiden keamanan terbaru beserta tingkat keparahannya.
- `/quarantine`: Memeriksa daftar IP terblokir dengan tombol pembebasan (*pardon*) instan.
