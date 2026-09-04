# Laravel Security Defense — Dokumentasi Integrasi & Kustomisasi

Dokumentasi modular untuk mengintegrasikan, mengonfigurasi, dan mengkustomisasi
package **`mixudev/security-defense`** ke dalam aplikasi Laravel Anda.

Dokumen ini adalah panduan praktis (how-to). Untuk detail arsitektur & keputusan
desain tingkat dalam, lihat folder [`docs/ai/`](./ai/README.md) (AI living docs).

---

## Daftar Modul

| # | File | Isi |
|---|------|-----|
| 1 | [`01-installation.md`](./01-installation.md) | Prasyarat, install via Composer, publish, migrate, auto-discovery |
| 2 | [`02-integration.md`](./02-integration.md) | Cara PANGIL package: WAF middleware, telemetry auth, facade programatik, domain events |
| 3 | [`03-alert-channels.md`](./03-alert-channels.md) | Konfigurasi channel alert: Database, Telegram, Discord, Webhook, Email + cara test |
| 4 | [`04-dashboard.md`](./04-dashboard.md) | Dashboard SIEM: akses, routing, theming (dark/light), publish views |
| 5 | [`05-customization.md`](./05-customization.md) | Customisasi lanjutan: rule kustom, channel kustom, threat source kustom, config tuning |
| 6 | [`06-security-hardening.md`](./06-security-hardening.md) | Hardening produksi: Redis cache, quarantine DB, block empty UA, best practice |
| 7 | [`07-testing.md`](./07-testing.md) | Menjalankan test suite + diagnostic channel via artisan |
| 8 | [`08-troubleshooting.md`](./08-troubleshooting.md) | FAQ & penyelesaian masalah umum |
| 9 | [`09-telegram-bot.md`](./09-telegram-bot.md) | Interactive Telegram Bot: Webhook produksi vs polling lokal, monitoring kesehatan & metrik |

---

## Ringkasan Alur Integrasi

```text
1. Install & publish  →  composer require + vendor:publish + migrate
2. Aktifkan WAF       →  register RequestThreatScanner middleware
3. Kirim telemetry    →  Event::listen auth (Failed/Login/Lockout) -> SecurityDefense::record()
4. Konfigurasi alert  →  .env channel + (opsional) queue
5. (Opsional) UI      →  dashboard SIEM otomatis di /security-defense (local-only)
```

Mulai dari [01-installation.md](./01-installation.md).

---

## Persyaratan

- PHP `^8.2`
- Laravel `^10.0 | ^11.0 | ^12.0 | ^13.0`
- Komponen Illuminate: support, database, cache, http, events
