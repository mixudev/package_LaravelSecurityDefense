# Configuration Reference — `mixudev/security-defense`

File konfigurasi utama terletak pada:
`config/security-defense.php`

Konfigurasi ini bertindak sebagai **single source of control**. Tidak ada nilai ambang batas (threshold), time window, atau channel behavior yang di-hardcode.

---

## Contoh Struktur Konfigurasi

```php
return [
    /*
    |--------------------------------------------------------------------------
    | Master Enable Switch
    |--------------------------------------------------------------------------
    | Mengaktifkan atau menonaktifkan seluruh fungsionalitas security defense.
    */
    'enabled' => env('SECURITY_DEFENSE_ENABLED', true),

    /*
    |--------------------------------------------------------------------------
    | Cache Store
    |--------------------------------------------------------------------------
    | Driver cache yang digunakan untuk state tracking dan deduplication.
    | Jika null, akan menggunakan default cache store Laravel.
    */
    'cache_store' => env('SECURITY_DEFENSE_CACHE_STORE', null),

    /*
    |--------------------------------------------------------------------------
    | Detection Engine & Rules
    |--------------------------------------------------------------------------
    */
    'detection' => [
        'enabled' => true,

        'rules' => [
            'brute_force' => [
                'enabled' => true,
                'threshold' => 10,       // Max kegagalan dalam window
                'window' => 60,          // Window waktu (detik)
                'severity' => 'high',
            ],

            'credential_stuffing' => [
                'enabled' => true,
                'threshold' => 8,        // Max user berbeda yang dicoba dari 1 IP
                'window' => 120,         // Window waktu (detik)
                'severity' => 'critical',
            ],

            'distributed_spray' => [
                'enabled' => true,
                'threshold' => 5,        // Max IP berbeda yang menyerang 1 target
                'window' => 300,         // Window waktu (detik)
                'severity' => 'high',
            ],

            'rate_limit_bypass' => [
                'enabled' => true,
                'threshold' => 15,       // Max rotasi client identity/spoof headers
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
                'max_speed_kmh' => 900,  // Kecepatan perpindahan maksimum realistis (pesawat)
                'window' => 3600,        // 1 jam
                'severity' => 'high',
            ],
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Alert Channels
    |--------------------------------------------------------------------------
    */
    'alerts' => [
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
    | Deduplication
    |--------------------------------------------------------------------------
    */
    'deduplication' => [
        'enabled' => true,
        'window' => 300, // Detik penekanan notifikasi untuk fingerprint identik
    ],

    /*
    |--------------------------------------------------------------------------
    | Prevention Middleware
    |--------------------------------------------------------------------------
    */
    'middleware' => [
        'payload_scanner' => [
            'enabled' => true,
            'action' => 'block', // 'block' atau 'log_only'
            'response_status' => 403,
            'response_message' => 'Suspicious request payload detected and blocked.',
        ],
    ],
];
```
