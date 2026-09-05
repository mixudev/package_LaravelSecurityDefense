# Arsitektur & Prinsip Desain

Prinsip fundamental dan arsitektur pipeline pertahanan `mixudev/security-defense`.

---

## 1. Filosofi Utama

> **"Authentication adalah penjaga pintu, Security Defense adalah kamera pengawas dan perisai proaktif."**

Package ini secara sengaja **tidak menduplikasi** tanggung jawab autentikasi:
- Tidak mengelola tabel akun, session cookie, token JWT, atau hashing password pengguna.
- Mengonsumsi telemetri keamanan dari aplikasi, mengorelasikan anomali dari berbagai vektor serangan, mengisolasi penyerang (Fail2Ban IP Quarantine), dan mengirimkan alert terformat ke tim operasi.

---

## 2. Diagram Alur Pipeline Keamanan

```text
Request HTTP Masuk / Telemetri Event Autentikasi
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│ Pipeline Pertahanan mixudev/security-defense                │
│                                                             │
│  [1. Lapisan Karantina IP Aktif]                            │
│      └── Tolak instan HTTP 429 jika IP terdaftar karantina  │
│          (Menghemat 99% CPU regex saat terjadi DoS masif)   │
│                                                             │
│  [2. Middleware WAF (RequestThreatScanner)]                 │
│      ├── Pengecekan ReDoS Bounded String                    │
│      ├── Fingerprinting User-Agent Scanner (sqlmap, nikto)  │
│      ├── Deteksi Path Reconnaissance (.env, .git, dump DB)  │
│      ├── Inspeksi Injeksi Payload (SQLi, XSS, RCE, Traversal│
│      └── Auto-jail IP penyerang ke karantina jika kritis    │
│                                                             │
│  [3. Bridge Telemetri & Engine Sanitizer]                   │
│      └── Sanitasi rekursif key rahasia (Zero-Leakage Policy)│
│                                                             │
│  [4. Engine Deteksi Anomali (8 Aturan Modular)]             │
│      ├── BruteForceRule                                     │
│      ├── CredentialStuffingRule                             │
│      ├── DistributedSprayRule                               │
│      ├── RateLimitBypassRule                                │
│      ├── PayloadInjectionRule                               │
│      ├── ImpossibleTravelRule                               │
│      ├── PathReconnaissanceRule                             │
│      └── UserAgentAnomalyRule                               │
│                                                             │
│  [5. Compound Threat Scoring Engine]                        │
│      └── Akumulasi bobot risiko antar vektor per entitas    │
│          Memicu CRITICAL compound_threat saat skor >= 100   │
│                                                             │
│  [6. Deduplikasi & Pembatas Disk Database]                  │
│      ├── Alert Rate Limiter (Maks 60 alert/menit ke DB)     │
│      └── Deduplikasi Fingerprint SHA-256                    │
│                                                             │
│  [7. Dispatcher Notifikasi Multi-Channel]                   │
│      ├── DatabaseChannel (Tabel security_alerts)            │
│      ├── TelegramChannel (Sync / Background Queue)          │
│      ├── DiscordChannel (Sync / Background Queue)           │
│      ├── WebhookChannel (Sync / Background Queue via HMAC)  │
│      └── MailChannel (Native Laravel Mail)                  │
│                                                             │
│  [8. Domain Events Lifecycle]                               │
│      ├── ThreatDetected                                     │
│      ├── SecurityAlertCreated                               │
│      └── SecurityAlertResolved                              │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Kebijakan Zero-Leakage (Privasi Data)

Semua telemetri yang masuk ke dalam objek `SecurityEvent` dan model `SecurityAlert` wajib melewati kelas `Sanitizer`.
Setiap key sensitif (`password`, `token`, `secret`, `authorization`, `cookie`, `credit_card`) diganti secara permanen menjadi string `[REDACTED]` untuk menjamin tidak ada kredensial pengguna yang bocor ke database alert, log sistem, maupun pesan webhook pihak ketiga.
