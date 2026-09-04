# Security Defense AI Living Documentation

Selamat datang di living documentation package `mixudev/security-defense`.

Dokumentasi ini dikelola secara berkelanjutan selama pengembangan untuk mencatat seluruh keputusan arsitektur, rincian teknis implementasi, konfigurasi, integrasi, strategi pengujian, dan catatan keamanan.

## Daftar Dokumen

1. [ARCHITECTURE.md](ARCHITECTURE.md) - Desain arsitektur, boundary, data flow, dan pemisahan tanggung jawab (Auth vs Defense).
2. [DECISIONS.md](DECISIONS.md) - Architecture Decision Records (ADR) dengan alasan, alternatif, dan trade-off.
3. [IMPLEMENTATION.md](IMPLEMENTATION.md) - Rincian implementasi komponen (Contracts, DTO, Rules, Engine, Channels, Middleware).
4. [SECURITY.md](SECURITY.md) - Prinsip dan standar keamanan data (sanitasi, credential redaction, safe logging).
5. [CONFIGURATION.md](CONFIGURATION.md) - Referensi lengkap `config/security-defense.php` dan behavior setiap opsi.
6. [INTEGRATION.md](INTEGRATION.md) - Panduan integrasi auth adapter, alert channels (Telegram, Discord, Webhook), dan middleware.
7. [TESTING.md](TESTING.md) - Strategi pengujian unit, feature, coverage, dan validasi scenario.
8. [CHANGELOG.md](CHANGELOG.md) - Riwayat perubahan dan penambahan fitur secara kronologis.
9. [TODO.md](TODO.md) - Task list terorganisir per fase pengerjaan.

## Filosofi Utama

> **"Authentication adalah penjaga pintu, Security Defense adalah kamera pengawas."**

Package ini tidak menduplikasi fitur authentication (user management, lockout, audit log umum, captcha, atau rate limiter auth bawaan), melainkan mengonsumsi telemetry event/data, mendeteksi korelasi anomali, melakukan deduplikasi, mengirimkan alert ke berbagai channel, serta menyediakan WAF-level prevention middleware untuk mendeteksi payload berbahaya.
