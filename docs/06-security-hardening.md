# 06 — Security Hardening (Konfigurasi Produksi)

Langkah opsional untuk memperkuat package saat dijalankan di produksi.

---

## 1. Wajib: Gunakan Cache Driver Redis / Memcached

Package menyimpan detection counters (sliding window), skor threat, dedup, dan
quarantine di cache. Driver `file` / `array` **hilang pada restart** — artinya
ada jendela bypass perlindungan saat aplikasi boot.

Di `.env` aplikasi:

```env
CACHE_STORE=redis
# atau
CACHE_STORE=memcached
```

Atau tentukan store khusus package:

```env
SECURITY_DEFENSE_CACHE_STORE=redis
```

> Dengan driver distributed, state bertahan lintas restart & multi-server.

---

## 2. Aktifkan Quarantine Persisten di Database

Quarantine berbasis cache hilang saat cache di-flush. Untuk durability penuh,
aktifkan penyimpanan DB:

```env
SECURITY_QUARANTINE_ENABLED=true
SECURITY_QUARANTINE_PERSIST_DB=true
```

Pastikan migration `security_quarantines` sudah dijalankan (`php artisan migrate`).
Cache = fast path, DB = authoritative fallback. Semua request dari IP
ter-quarantine ditolak 429 di middleware.

---

## 3. Blokir Client Tanpa User-Agent

Beberapa scanner mengirim request tanpa header `User-Agent`:

```env
SECURITY_DEFENSE_BLOCK_EMPTY_UA=true
```

Request tanpa UA akan ditandai anomali (severity medium) dan bisa diblokir.

---

## 4. Mode Scanner Payload (block vs log_only)

```env
# config/security-defense.php
'middleware' => [
    'payload_scanner' => [
        'action' => 'block',   // 'block' = HTTP 403, 'log_only' = hanya catat
        'response_status' => 403,
        'excluded_paths' => [
            // 'api/webhooks/*'  <- kecualikan endpoint yang memang terima input mentah
        ],
    ],
],
```

> Saat onboarding, mulai dengan `log_only` untuk menghindari false-positive
> memblokir trafik sah, lalu beralih ke `block` setelah tuning.

---

## 5. Self-Defense Hardening (Bawaan, Jangan Dimatikan)

Package punya lapisan self-defense bawaan yang MELINDUNGI dirinya sendiri dari
serangan (ReDoS / memory exhaustion / disk flood):

| Parameter | Default | Fungsi |
|-----------|---------|--------|
| `hardening.max_inspection_length` | 4096 | Batas panjang string yang discan regex (anti-ReDoS) |
| `hardening.max_traversal_depth` | 5 | Batas kedalaman rekursi array (anti memory) |
| `hardening.alert_rate_limit.max_alerts_per_minute` | 60 | Batas tulis alert per menit (anti disk flood) |
| `hardening.max_alert_metadata_size` | 16384 | Truncate metadata alert besar |

Sebaiknya jangan dinaikkan tanpa alasan kuat.

---

## 6. Zero-Leakage (Privasi Otomatis)

Semua field sensitif otomatis di-redact menjadi `[REDACTED]` sebelum
disimpan/dikirim: `password`, `token`, `cookie`, `secret`, header `authorization`,
dsb. Tidak ada kredensial yang bocor ke log, DB, webhook, atau email.

---

## 7. Dashboard — Akses Produksi yang Aman

Dashboard default **local-only** (`local_only=true`). Untuk akses pribadi di
production, JANGAN cuma set `local_only=false`. Gunakan Gate kustom:

```php
// AppServiceProvider::boot()
use Illuminate\Support\Facades\Gate;

Gate::define('viewSecurityDefenseDashboard', function ($user) {
    return $user !== null && $user->is_admin === true;
});
```

Perilaku `EnsureLocalAccess`:

- `local` environment + IP di `allowed_ips` → izin
- Gate `viewSecurityDefenseDashboard` → true → izin
- selain itu → 403

> Dashboard memakai **Tailwind CDN browser runtime** (tanpa build step).
> Jika diexpose non-local, ganti ke **Tailwind compiled (Vite)** untuk purge CSS
> dan hilangkan dependency CDN eksternal demi CSP/offline.

---

## 8. Rekomendasi Endpoint Webhook Penerima

Payload webhook/SIEM ditandatangani HMAC-SHA256 (`X-Signature: sha256=...`).
Selalu verifikasi signature di sisi penerima sebelum memproses (lihat
[03-alert-channels.md](./03-alert-channels.md) untuk contoh verifikasi).

---

## 9. Checklist Produksi

- [ ] Cache driver Redis/Memcached aktif
- [ ] `SECURITY_QUARANTINE_PERSIST_DB=true` + migrate
- [ ] Queue worker jalan jika `SECURITY_DEFENSE_QUEUE_ENABLED=true`
- [ ] Scanner di-mode `block` setelah tuning
- [ ] Dashboard hanya lewat Gate kustom (bukan `local_only=false` polos)
- [ ] Tambahkan `allowed_ips` server Anda bila perlu
- [ ] Review `.env` — jangan commit token/channel key ke git

---

## 10. Enterprise Scale & Aggressive Bot Hunting

Disediakan lapisan agresif yang hemat CPU untuk menangani jutaan request /
bot scraping / auto-inject, tanpa membebani server.

### 10a. Per-IP Request Flood Limiter (DDoS / scraper guard)

Middleware `RequestThreatScanner` kini punya counter per-IP **O(1) atomic**
(sebelum semua pemeriksaan regex). IP yang melebihi kapasitas per jendela waktu
langsung ditolak 429 dan akhirnya auto-quarantine.

```env
# Aktif (default true)
SECURITY_DEFENSE_FLOOD_PROTECTION=true
```

Config (`config/security-defense.php`):

```php
'middleware' => [
    'request_flood' => [
        'enabled' => true,
        'max_requests_per_second' => 200, // kapasitas per-IP per jendela
        'window' => 5,                    // detik per jendela counter
        'jail_after_exceeding' => 2,      // jendela beruntun melebihi cap -> jail
    ],
],
```

> Tuning: untuk backend di balik reverse proxy / load balancer dengan banyak
> pengguna NAT, naikkan `max_requests_per_second` atau minta proxy menulis IP asli
> sebagai `REMOTE_ADDR`. Serangan masif memicu `fail-closed` (langsung tolak).

### 10b. Fast-path Payload Scan (hemat CPU saat jutaan request)

Secara default, `PayloadInjectionRule::inspect()` TIDAK dijalankan untuk request
tanpa query string dan tanpa body (GET polos). Ini memotong biaya regex hampir
ke nol untuk trafik normal GET/HEAD.

```php
'middleware' => [
    'payload_scanner' => [
        'scan_empty_requests' => false, // true = selalu scan (lebih agresif, CPU lebih tinggi)
    ],
],
```

### 10c. HTTP Method Abuse

- `TRACE` / `TRACK` diblokir **tanpa syarat** (vektor reflected-XSS via TRACE,
  tidak ada kegunaan sah).
- Flood `OPTIONS` / `HEAD` dari bot terpotong oleh flood limiter (10a).

### 10d. Bot Hunting Lebih Luas (User-Agent)

Daftar scanner `UserAgentAnomalyRule` diperluas: sqlmap, nikto, dirbuster,
gobuster, wpscan, masscan, nmap, acunetix, nessus, nuclei, zgrab, hydra,
**ffuf, dirsearch, zmap, cadaver, wfuzz, testssl, whatweb, sublist3r, katana,
jaeles, dalfox, xsstrike, commix, tplmap, arachni, wapiti**.

Aktifkan (default `true`):

```php
'detection' => [
    'rules' => [
        'user_agent_anomaly' => [
            'block_known_scanners' => true,
        ],
    ],
],
```

### 10e. Threat Scoring race-free

`ThreatScoringEngine` kini memakai **counter atomik** (`cache->increment()`) untuk
skor agregat (bukan read-modify-write yang racy), dan membatasi cache records
(`detection.scoring.max_records`, default 50) agar memori cache tidak tumbuh
tanpa batas selama serangan berkelanjutan.

---

Lanjut ke [07-testing.md](./07-testing.md).
