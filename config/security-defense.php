<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Master Enable Switch
    |--------------------------------------------------------------------------
    | Globally enables or disables security defense analysis, alerting, and
    | preventive middleware.
    */
    'enabled' => env('SECURITY_DEFENSE_ENABLED', true),

    /*
    |--------------------------------------------------------------------------
    | Cache Store
    |--------------------------------------------------------------------------
    | The cache repository used to track sliding-window frequency counters
    | and alert deduplication keys. If null, application default cache is used.
    */
    'cache_store' => env('SECURITY_DEFENSE_CACHE_STORE', null),

    /*
    |--------------------------------------------------------------------------
    | Cache Prefix
    |--------------------------------------------------------------------------
    */
    'cache_prefix' => 'security_defense:',

    /*
    |--------------------------------------------------------------------------
    | Anomaly Detection Engine
    |--------------------------------------------------------------------------
    */
    'detection' => [
        'enabled' => true,

        'rules' => [
            'brute_force' => [
                'enabled' => true,
                'threshold' => 10,       // Max failed attempts before flagging
                'window' => 60,          // Time window in seconds
                'severity' => 'high',
                'events' => ['LoginFailed', 'OTP_FAILED'],
            ],

            'credential_stuffing' => [
                'enabled' => true,
                'threshold' => 8,        // Max distinct identifiers targeted from single IP
                'window' => 120,         // Time window in seconds
                'severity' => 'critical',
                'events' => ['LoginFailed'],
            ],

            'distributed_spray' => [
                'enabled' => true,
                'threshold' => 5,        // Max distinct IPs targeting single identifier
                'window' => 300,         // Time window in seconds
                'severity' => 'high',
                'events' => ['LoginFailed'],
            ],

            'rate_limit_bypass' => [
                'enabled' => true,
                'threshold' => 15,       // Max header/identifier cycling attempts
                'window' => 60,          // Time window in seconds
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
                'max_speed_kmh' => 900,  // Max realistic ground/air speed in km/h
                'window' => 3600,        // 1 hour window to compare location coordinates
                'severity' => 'high',
                'events' => ['LoginSucceeded', 'NewDeviceLoginDetected'],
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
    | Alert Deduplication
    |--------------------------------------------------------------------------
    */
    'deduplication' => [
        'enabled' => true,
        'window' => 300, // Seconds to suppress duplicate alerts with identical fingerprint
    ],

    /*
    |--------------------------------------------------------------------------
    | Active Prevention Middleware (RequestThreatScanner)
    |--------------------------------------------------------------------------
    */
    'middleware' => [
        'payload_scanner' => [
            'enabled' => true,
            'action' => 'block', // 'block' or 'log_only'
            'response_status' => 403,
            'response_message' => 'Suspicious request payload detected and blocked.',
            'excluded_paths' => [
                // e.g. 'api/webhooks/*'
            ],
        ],
    ],
];
