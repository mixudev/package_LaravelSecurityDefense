# Architecture Overview — `mixudev/security-defense`

## 1. High-Level Architectural Model

Package ini didesain berdasarkan arsitektur berbasis event dan pipeline deteksi anomali modular yang decoupled dari framework auth spesifik:

```text
Laravel Application / Auth Package
         │
         ▼ (Dispatches Authentication/Security Events)
┌─────────────────────────────────────────────────────────────┐
│ mixudev/security-defense                                    │
│                                                             │
│  [1. ThreatSource Contract]                                 │
│      ├── GenericArraySource                                 │
│      ├── LaravelAuthEventAdapter                            │
│      └── RequestSourceAdapter                               │
│         │ (Normalisasi & Sanitasi Credential)               │
│         ▼                                                   │
│      SecurityEvent DTO                                      │
│                                                             │
│  [2. AnomalyDetector Engine]                                │
│      ├── BruteForceRule                                     │
│      ├── CredentialStuffingRule                             │
│      ├── DistributedSprayRule                               │
│      ├── RateLimitBypassRule                                │
│      ├── PayloadInjectionRule                               │
│      └── ImpossibleTravelRule                               │
│         │ (Mengevaluasi Event terhadap Rules aktif)         │
│         ▼                                                   │
│      SecurityThreat DTO                                     │
│                                                             │
│  [3. Deduplication & Alerting Subsystem]                    │
│      ├── AlertDeduplicator (Fingerprint + Cache Window)     │
│      │     [Suppressed jika duplikat dalam window]          │
│      │     [Lanjut jika baru]                               │
│      ▼                                                      │
│  [4. Persistence & Channel Dispatcher]                      │
│      ├── DatabaseChannel -> Model: SecurityAlert            │
│      ├── TelegramChannel (HTTP Client, graceful skip)       │
│      ├── DiscordChannel (HTTP Client, graceful skip)        │
│      └── WebhookChannel (HTTP Client, SIEM payload)         │
│                                                             │
│  [5. Active Prevention Layer]                               │
│      └── RequestThreatScanner Middleware                    │
│          (Inspeksi request query/body/headers sebelum WAF)  │
│                                                             │
│  [6. Framework Events]                                      │
│      ├── ThreatDetected                                     │
│      ├── SecurityAlertCreated                               │
│      └── SecurityAlertResolved                              │
└─────────────────────────────────────────────────────────────┘
```

## 2. Pemisahan Tanggung Jawab (Separation of Concerns)

| Domain | Auth (Penjaga Pintu) | Security Defense (Kamera Pengawas) |
|---|---|---|
| **Tanggung Jawab** | Memverifikasi identitas pengguna, password hashing, session/token management, MFA/OTP verification. | Menganalisis korelasi anomali antar-event, deteksi serangan terdistribusi, deduplikasi alert, notifikasi SIEM/chatOps, payload scanning. |
| **Penyimpanan State** | User table, sessions table, password resets table, personal access tokens. | Security alerts table, sliding-window cache counter untuk fingerprint anomaly. |
| **Tindakan** | Mengizinkan/menolak login, lockout akun lokal, issue JWT/token. | Menerbitkan SecurityThreat, mencatat SecurityAlert, notifikasi tim SOC/Admin, blocking request jika payload terbukti berbahaya. |

## 3. Komponen Utama

### A. Contracts Layer (`src/Contracts/`)
- `ThreatSource`: Mengubah event eksternal/data array menjadi `SecurityEvent` DTO yang ternormalisasi.
- `DetectionRule`: Interface untuk rule deteksi independen. Menerima `SecurityEvent` dan mengembalikan `?SecurityThreat`.
- `ThreatDetector`: Contract untuk engine utama yang mengorkestrasi evaluasi rule dan event dispatching.
- `AlertChannel`: Contract untuk delivery target (`DatabaseChannel`, `TelegramChannel`, `DiscordChannel`, `WebhookChannel`).
- `AlertDeduplicatorInterface`: Contract untuk evaluasi dan penyimpanan fingerprint deduplication.

### B. DTO Layer (`src/DTO/`)
- `SecurityEvent`: Immutable data value object berisi `ip`, `identifier`, `eventType`, `timestamp`, `userAgent`, `metadata`.
- `SecurityThreat`: Hasil evaluasi deteksi berisi `severity`, `threatType`, `fingerprint`, `metadata`, `rule`.

### C. Detection Engine & Rules (`src/Detection/`, `src/Rules/`)
- Rules menggunakan state storage berbasis Laravel Cache (Atomic increment / sliding window timestamps) sehingga stateless pada level PHP process, thread-safe, dan cluster-compatible (Redis, Memcached, Database Cache).

### D. Alerting & Deduplication (`src/Channels/`, `src/Services/`)
- Mencegah notification storm dengan mengunci `fingerprint` dalam jangka waktu `deduplication.window` (detik).
- Alert wajib tersimpan ke Database, sedangkan channel chatOps/eksternal bersifat fail-safe (jika unconfigured atau jaringan down, alert database tidak gagal).
