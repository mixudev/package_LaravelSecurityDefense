# 09 — Interactive Telegram Bot & Monitoring

Package `mixudev/security-defense` dilengkapi dengan sistem **Interactive Telegram Bot Control Panel**. Bot ini tidak hanya mengirimkan notifikasi saat ancaman terdeteksi, tetapi juga menyediakan dashboard interaktif melalui Telegram untuk memantau kesehatan server, metrik keamanan, log insiden, dan status karantina IP.

---

## Fitur Utama

- **Desain Enterprise Bersih**: Menggunakan format monospace dan bracket (`[OK]`, `[FAIL]`, `[CRITICAL]`, `•`) dengan minim emoji agar tampak rapi dan profesional.
- **Inline Keyboard Menu**: Tombol interaktif yang memperbarui pesan secara langsung (*in-place edit*) tanpa mengotori ruang obrolan.
- **Tombol Native "Menu"**: Pendaftaran otomatis ke Telegram API (`setMyCommands`) agar tombol menu biru muncul di pojok kiri bawah aplikasi Telegram pengguna.
- **Otorisasi Ketat**: Hanya Chat ID terdaftar (`SECURITY_TELEGRAM_CHAT_ID`) yang dapat mengakses data diagnostik sistem.

---

## Arsitektur: Webhook vs Long-Polling

| Karakteristik | Mode Webhook (Produksi / Hosting) | Mode Polling (Localhost / Laptop) |
|---|---|---|
| **Target Environment** | Shared Hosting (cPanel), VPS, Cloud, Server Produksi | Laptop Developer (`127.0.0.1` / Localhost) |
| **Kebutuhan Worker/Daemon** | **TIDAK PERLU** worker sama sekali | Perlu process berjalan di terminal |
| **Beban RAM Server** | **0 MB** (hanya berjalan saat ada request masuk) | Menjalankan proses PHP di CLI |
| **Mekanisme** | Telegram yang "mengetuk" URL website via HTTP POST | Aplikasi yang secara berkala menanyakan data ke Telegram |
| **Command Setup** | `php artisan security:telegram-webhook set` | `php artisan security:telegram-poll` |

---

## 1. Setup di Server Produksi / Shared Hosting (Mode Webhook)

Di lingkungan hosting atau VPS yang sudah memiliki domain publik HTTPS (contoh: `https://aplikasi-anda.com`), **Anda tidak membutuhkan worker, daemon, ataupun background process!**

### Langkah 1: Pastikan Kredensial di `.env`
```env
SECURITY_TELEGRAM_BOT_TOKEN=8788019703:AAH2OjHDKe6IWX_n0E4JgbJsOumHq__I_AY
SECURITY_TELEGRAM_CHAT_ID=8741993336
```

### Langkah 2: Daftarkan Webhook (Cukup 1 Kali)
Jalankan perintah ini melalui terminal / SSH di server:
```bash
php artisan security:telegram-webhook set
```
Command ini akan otomatis:
1. Membaca domain dari `APP_URL` Anda dan mendaftarkan URL: `https://aplikasi-anda.com/security-defense/telegram/webhook`.
2. Mendaftarkan tombol native "Menu" ke Telegram API (`setMyCommands`).
3. Menghasilkan token rahasia webhook (*HMAC auto-secret*) untuk memastikan hanya server resmi Telegram yang dapat mengakses endpoint tersebut.

### Langkah 3: Selesai!
Setiap kali Anda menekan tombol menu di Telegram, server Telegram akan mengirimkan request HTTP biasa ke website Anda. Controller Laravel akan meresponsnya secara instan seperti halaman web pada umumnya. **Shared hosting cPanel murah sekalipun dijamin bekerja 100% tanpa kendala.**

#### Perintah Tambahan untuk Manajemen Webhook:
```bash
# Cek status koneksi webhook saat ini
php artisan security:telegram-webhook info

# Hapus webhook (jika ingin beralih kembali ke mode polling)
php artisan security:telegram-webhook delete
```

---

## 2. Setup di Laptop / Localhost (Mode Long-Polling)

Karena alamat laptop Anda adalah `localhost` (`127.0.0.1`), server Telegram di internet tidak dapat menghubungi laptop Anda secara langsung. Oleh karena itu, gunakan mode **Polling**.

### Menjalankan Poller Manual:
Buka terminal dan jalankan:
```bash
php artisan security:telegram-poll
```
Buka Telegram Anda, cari bot Anda, dan kirim `/start`. Bot akan langsung merespons secara real-time.

### Integrasi Otomatis dengan `composer run dev`:
Agar bot otomatis aktif saat Anda menjalankan server development lokal, tambahkan poller ke dalam script `dev` pada file `composer.json`:

```json
"dev": [
    "Composer\\Config::disableProcessTimeout",
    "npx concurrently -c \"#93c5fd,#c4b5fd,#fdba74,#34d399\" \"php artisan serve\" \"php artisan queue:listen --tries=1\" \"npm run dev\" \"php artisan security:telegram-poll\" --names='server,queue,vite,bot'"
]
```
Kini setiap kali Anda menjalankan `composer run dev`, bot akan langsung aktif di latar belakang.

---

## 3. Alternatif: Mode Cron Job di Shared Hosting

Jika hosting Anda tidak mengizinkan Webhook publik dan tidak memiliki worker daemon, Anda dapat menggunakan Laravel Scheduler bawaan cPanel (`schedule:run`) dengan menambahkan jadwal di `routes/console.php`:

```php
use Illuminate\Support\Facades\Schedule;

// Menjalankan pengecekan update Telegram setiap menit
Schedule::command('security:telegram-poll --once')->everyMinute();
```

---

## 4. Daftar Perintah & Navigasi Menu

Pengguna dapat menekan tombol menu di Telegram atau mengetik perintah berikut:

- `/start` atau `/menu`: Membuka Control Panel Dashboard utama dengan tombol interaktif.
- `/health`: Menjalankan pemeriksaan kesehatan sistem secara langsung:
  - Latensi ping Database (dalam milidetik / ms).
  - Status koneksi Cache store.
  - Sisa kapasitas penyimpanan disk storage (GB dan persentase).
  - Penggunaan memori PHP saat ini dan peak usage.
  - Lingkungan aplikasi (`local`, `production`) dan status Debug.
- `/metrics` atau `/status`: Menampilkan ringkasan ancaman keamanan 24 jam terakhir (jumlah Critical, High, Medium, Low) serta status modul WAF (Payload Scanner, Flood Protection, Auto Quarantine).
- `/incidents` atau `/alerts`: Mengambil 5 data serangan keamanan terakhir langsung dari tabel database `security_alerts`.
- `/quarantine`: Menampilkan daftar alamat IP yang sedang diisolasi oleh sistem Fail2Ban beserta hitung mundur sisa waktu hukumannya.
- `/help`: Menampilkan ringkasan panduan bantuan perintah.

---

## 5. Keamanan Akses (Access Control)

Untuk mencegah pengguna Telegram lain memeriksa statistik server Anda:
1. Setiap pesan atau klik tombol yang masuk akan diperiksa terhadap `SECURITY_TELEGRAM_CHAT_ID`.
2. Jika Chat ID pengirim tidak cocok dengan konfigurasi, bot akan menolak request secara otomatis dengan pesan:
   ```text
   [SECURITY DEFENSE]
   Access Denied: Chat ID 123456789 is not authorized to access system diagnostics.
   ```
