# Configuration Reference — `mixudev/security-defense`

Bagian `epistemic` bersifat eksperimental dan belum siap produksi. Default `epistemic.enabled=false` dan `epistemic.response.enabled=false`; jangan mengaktifkan enforcement tanpa adapter yang diaudit.

File konfigurasi utama terletak pada:
`config/security-defense.php`

Konfigurasi ini bertindak sebagai **single source of control**. Tidak ada nilai ambang batas (threshold), time window, bobot scoring, durasi quarantine, atau channel behavior yang di-hardcode.

---

## Rincian Opsi Konfigurasi Lengkap

### Opsi `epistemic`

| Kunci | Default | Fungsi |
|---|---:|---|
| `epistemic.enabled` | `false` | Mengaktifkan analisis epistemik eksperimental. |
| `epistemic.graph.max_depth` | `8` | Batas kedalaman traversal graph. |
| `epistemic.graph.max_nodes` | `500` | Batas node graph. |
| `epistemic.graph.window_seconds` | `900` | Jendela waktu graph. |
| `epistemic.limits.max_events` | `500` | Batas event per analisis. |
| `epistemic.limits.max_evidence` | `500` | Batas evidence non-AI per analisis. |
| `epistemic.limits.max_metadata_bytes` | `4096` | Batas metadata. |
| `epistemic.ai.max_evidence` | `20` | Batas evidence dari provider AI. |
| `epistemic.ai.allowed_future_seconds` | `60` | Toleransi timestamp AI ke masa depan. |
| `epistemic.memory.max_patterns` | `10000` | Batas pola memory berbasis cache. |
| `epistemic.memory.retention_days` | `30` | Retensi pola dan replay guard feedback. |
| `epistemic.response.enabled` | `false` | Enforcement response; default off. |
| `epistemic.response.adapter` | `null` | Adapter response eksplisit; tanpa adapter tidak ada enforcement. |

Evidence AI yang tervalidasi dapat ikut korelasi dan memengaruhi assessment, tetapi tetap advisory. `NoopResponseAdapter` tidak melakukan enforcement. Fitur epistemic belum siap produksi.

### Konfigurasi cache dan upgrade

Setelah mengubah `config/security-defense.php` pada aplikasi dengan config cache, jalankan `php artisan config:clear` saat migrasi, lalu `php artisan config:cache` setelah verifikasi. Jangan mengaktifkan `epistemic.enabled` atau `epistemic.response.enabled` hanya karena file konfigurasi sudah dipublish. Pastikan cache store mendukung lock bila deployment mengandalkan serialisasi memory; fallback counter atomik tetap berlaku bila lock tidak tersedia.

```php
return [
    /*
    |--------------------------------------------------------------------------
    | Master Enable Switch
    |--------------------------------------------------------------------------
    | Mengaktifkan atau menonaktifkan seluruh modul security defense secara global.
    */
    'enabled' => env('SECURITY_DEFENSE_ENABLED', true),

    /*
    |--------------------------------------------------------------------------
    | Cache Store & Prefix
    |--------------------------------------------------------------------------
    | Cache driver yang digunakan untuk counter sliding-window, deduplikasi,
    | threat scoring, dan temporary IP quarantine.
    */
    'cache_store' => env('SECURITY_DEFENSE_CACHE_STORE', null),
    'cache_prefix' => 'security_defense:',

    /*
    |--------------------------------------------------------------------------
    | Self-Defense & Hardening (Zero Vulnerability Guarantee)
    |--------------------------------------------------------------------------
    */
    'hardening' => [
        // Batas maksimum karakter string yang diinspeksi regex (Anti-ReDoS)
        'max_inspection_length' => 4096,

        // Batas maksimum kedalaman array bertingkat (Anti-Memory Exhaustion)
        'max_traversal_depth' => 5,

        // Rate limiter penulisan alert ke database (Anti-Disk Exhaustion)
        'alert_rate_limit' => [
            'enabled' => true,
            'max_alerts_per_minute' => 60,
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Detection Engine & Compound Threat Scoring
    |--------------------------------------------------------------------------
    */
    'detection' => [
        'enabled' => true,

        // Korelasi ancaman multi-vektor
        'scoring' => [
            'enabled' => true,
            'threshold' => 100, // Skor akumulatif untuk memicu alert CRITICAL compound
            'window' => 900,    // Jendela waktu akumulasi (15 menit)
            'weights' => [
                'brute_force' => 35,
                'credential_stuffing' => 45,
                'distributed_spray' => 30,
                'rate_limit_bypass' => 20,
                'payload_injection' => 50,
                'impossible_travel' => 35,
                'path_reconnaissance' => 30,
                'user_agent_anomaly' => 25,
            ],
        ],

        'rules' => [
            'brute_force' => [
                'enabled' => true,
                'threshold' => 10,
                'window' => 60,
                'severity' => 'high',
                'events' => ['LoginFailed', 'OTP_FAILED'],
            ],

            'credential_stuffing' => [
                'enabled' => true,
                'threshold' => 8,
                'window' => 120,
                'severity' => 'critical',
                'events' => ['LoginFailed'],
            ],

            'distributed_spray' => [
                'enabled' => true,
                'threshold' => 5,
                'window' => 300,
                'severity' => 'high',
                'events' => ['LoginFailed'],
            ],

            'rate_limit_bypass' => [
                'enabled' => true,
                'threshold' => 15,
                'window' => 60,
                'severity' => 'medium',
            ],

            'payload_injection' => [
                'enabled' => true,
                'severity' => 'critical',
                'patterns' => [
                    'sqli' => true,
                    'xss' => true,
                    'traversal' => true,
                    'command_injection' => true,
                ],
            ],

            'impossible_travel' => [
                'enabled' => true,
                'max_speed_kmh' => 900,
                'window' => 3600,
                'severity' => 'high',
                'events' => ['LoginSucceeded', 'NewDeviceLoginDetected'],
            ],

            'path_reconnaissance' => [
                'enabled' => true,
                'severity' => 'high',
                'threshold' => 3,
                'window' => 120,
            ],

            'user_agent_anomaly' => [
                'enabled' => true,
                'severity' => 'medium',
                'block_known_scanners' => true,
            ],
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Alert Channels & Background Queuing
    |--------------------------------------------------------------------------
    */
    'alerts' => [
        // Offload pengiriman notifikasi ke background queue untuk zero latency
        'queue' => [
            'enabled' => env('SECURITY_DEFENSE_QUEUE_ENABLED', false),
            'connection' => env('SECURITY_DEFENSE_QUEUE_CONNECTION', null),
            'queue_name' => env('SECURITY_DEFENSE_QUEUE_NAME', 'security-alerts'),
        ],

        'database' => [
            'enabled' => true,
            'table' => 'security_alerts',
        ],

        'telegram' => [
            'enabled' => env('SECURITY_TELEGRAM_ENABLED', false),
            'bot_token' => env('SECURITY_TELEGRAM_BOT_TOKEN'),
            'chat_id' => env('SECURITY_TELEGRAM_CHAT_ID'),
            'timeout' => 5,
        ],

        'discord' => [
            'enabled' => env('SECURITY_DISCORD_ENABLED', false),
            'webhook_url' => env('SECURITY_DISCORD_WEBHOOK'),
            'timeout' => 5,
        ],

        'webhook' => [
            'enabled' => env('SECURITY_WEBHOOK_ENABLED', false),
            'url' => env('SECURITY_WEBHOOK_URL'),
            'secret' => env('SECURITY_WEBHOOK_SECRET'),
            'timeout' => 5,
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Alert Deduplication
    |--------------------------------------------------------------------------
    */
    'deduplication' => [
        'enabled' => true,
        'window' => 300, // Detik penekanan notifikasi untuk fingerprint identik
    ],

    /*
    |--------------------------------------------------------------------------
    | Active Prevention Middleware (RequestThreatScanner)
    |--------------------------------------------------------------------------
    */
    'middleware' => [
        'payload_scanner' => [
            'enabled' => true,
            'action' => 'block', // 'block' atau 'log_only'
            'response_status' => 403,
            'response_message' => 'Suspicious request payload detected and blocked.',
            'excluded_paths' => [],
        ],

        // Active Fail2Ban-Style IP Quarantine
        'quarantine' => [
            'enabled' => env('SECURITY_QUARANTINE_ENABLED', true),
            'duration' => 900,                // Durasi isolasi (15 menit)
            'auto_jail_on_critical' => true,  // Auto-jail saat ada serangan injeksi kritis
            'response_status' => 429,
            'response_message' => 'Your IP has been temporarily quarantined due to suspicious security activity.',
            'whitelist' => [
                '127.0.0.1',
                '::1',
            ],
        ],
    ],
];
```
