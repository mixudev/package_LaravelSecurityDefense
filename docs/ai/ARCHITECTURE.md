# Architecture Overview — `mixudev/security-defense`

## 1. High-Level Architectural Model

Package ini didesain dengan arsitektur pipeline pertahanan enterprise modular, stateless, dan decoupled dari framework auth:

```text
HTTP Request / Auth Telemetry
         │
         ▼
┌─────────────────────────────────────────────────────────────┐
│ mixudev/security-defense (Enterprise Architecture)          │
│                                                             │
│  [0. Active Defense & Quarantine Layer]                     │
│      └── IpQuarantineService                                │
│          (Instant reject HTTP 429 jika IP dalam karantina;  │
│           zero CPU regex overhead saat diserang)            │
│                                                             │
│  [1. Preventive WAF Middleware (RequestThreatScanner)]      │
│      ├── Anti-ReDoS Truncator (Max string bounds)           │
│      ├── UserAgentAnomalyRule (sqlmap, nikto, dirbuster)    │
│      ├── PathReconnaissanceRule (.env, .git, wp-login, etc) │
│      └── PayloadInjectionRule (SQLi, XSS, Path Traversal)   │
│          └── Auto-jail ke IpQuarantineService jika critical │
│                                                             │
│  [2. ThreatSource Adapter & Sanitizer]                      │
│      ├── GenericArraySource & RequestThreatSource           │
│      └── Sanitizer Engine (Depth limit & credential mask)   │
│         │                                                   │
│         ▼                                                   │
│      SecurityEvent DTO                                      │
│                                                             │
│  [3. AnomalyDetector Engine (8 Modular Rules)]              │
│      ├── BruteForceRule                                     │
│      ├── CredentialStuffingRule                             │
│      ├── DistributedSprayRule                               │
│      ├── RateLimitBypassRule                                │
│      ├── PayloadInjectionRule                               │
│      ├── ImpossibleTravelRule                               │
│      ├── PathReconnaissanceRule                             │
│      └── UserAgentAnomalyRule                               │
│         │                                                   │
│         ▼                                                   │
│      SecurityThreat DTO                                     │
│                                                             │
│  [4. ThreatScoringEngine (Multi-Vector Correlation)]        │
│      ├── Akumulasi bobot skor risiko per entitas/IP         │
│      └── Trigger compound_threat (CRITICAL) jika >= 100    │
│                                                             │
│  [5. Deduplication & Anti-Disk Flood Limiter]              │
│      ├── Alert Rate Limiter (Max 60 alerts/menit ke DB)     │
│      └── AlertDeduplicator (Fingerprint SHA-256 + Window)   │
│                                                             │
│  [6. Alert Persistence & Multi-Channel Dispatcher]          │
│      ├── DatabaseChannel (Mandatory Model: SecurityAlert)   │
│      ├── TelegramChannel (Sync / Background Queue)          │
│      ├── DiscordChannel (Sync / Background Queue)           │
│      └── WebhookChannel (Sync / Background Queue via HMAC)  │
│                                                             │
│  [7. Domain Events]                                         │
│      ├── ThreatDetected                                     │
│      ├── SecurityAlertCreated                               │
│      └── SecurityAlertResolved                              │
└─────────────────────────────────────────────────────────────┘
```

## 2. Pemisahan Tanggung Jawab (Separation of Concerns)

| Domain | Auth (Penjaga Pintu) | Security Defense (Kamera Pengawas & WAF) |
|---|---|---|
| **Tanggung Jawab** | Memverifikasi identitas pengguna, password hashing, session/token management, MFA/OTP verification. | Menganalisis korelasi anomali multi-vektor, mitigasi DoS, deduplikasi alert, IP quarantine, WAF payload scanning, dan pelaporan SIEM/chatOps. |
| **Penyimpanan State** | User table, sessions table, password resets table, personal access tokens. | Security alerts table, sliding-window cache counter untuk fingerprint anomaly dan temporary quarantine cache. |
| **Tindakan** | Mengizinkan/menolak login, lockout akun lokal, issue JWT/token. | Menerbitkan SecurityThreat, menaikkan Compound Risk Score, auto-jail IP penyerang, blocking request sebelum controller, mencatat SecurityAlert. |
