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
    | Cache Store & Prefix
    |--------------------------------------------------------------------------
    | Cache repository used for sliding-window counters, deduplication, and
    | temporary IP quarantine. If null, application default cache is used.
    */
    'cache_store' => env('SECURITY_DEFENSE_CACHE_STORE', null),
    'cache_prefix' => 'security_defense:',

    /*
    |--------------------------------------------------------------------------
    | Self-Defense & Hardening (Zero Vulnerability Guarantee)
    |--------------------------------------------------------------------------
    | Prevents the security defense package itself from becoming a denial-of-service
    | target via ReDoS, memory exhaustion, or alert database disk flooding.
    */
    'hardening' => [
        // Maximum string length to inspect per field before truncating (anti-ReDoS)
        'max_inspection_length' => 4096,

        // Maximum array recursion depth to inspect
        'max_traversal_depth' => 5,

        // Alert rate limiter to protect database disk from alert storms
        'alert_rate_limit' => [
            'enabled' => true,
            'max_alerts_per_minute' => 60,
        ],

        // Maximum alert metadata size (bytes) before truncation
        'max_alert_metadata_size' => 16384,
    ],

    /*
    |--------------------------------------------------------------------------
    | Anomaly Detection Engine & Rules
    |--------------------------------------------------------------------------
    */
    'detection' => [
        'enabled' => true,

        /*
        | Compound Threat Scoring Engine
        | Aggregates risk scores across multiple attack vectors within a sliding
        | window. If aggregate score exceeds threshold, triggers a critical alert.
        */
        'scoring' => [
            'enabled' => true,
            'threshold' => 100, // Aggregate score required to trigger compound threat
            'window' => 900,    // 15 minutes accumulation window
            'max_records' => 50, // Max threat records retained per entity (bounds cache memory)
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

            'path_reconnaissance' => [
                'enabled' => true,
                'severity' => 'high',
                'threshold' => 3,        // Number of probe hits in window
                'window' => 120,         // Window in seconds
            ],

            'user_agent_anomaly' => [
                'enabled' => true,
                'severity' => 'medium',
                'block_known_scanners' => true, // sqlmap, nikto, dirbuster, gobuster, etc.
                'block_empty_user_agent' => env('SECURITY_DEFENSE_BLOCK_EMPTY_UA', false), // Block requests with no User-Agent header
            ],
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Alert Channels & Background Queuing
    |--------------------------------------------------------------------------
    */
    'alerts' => [
        /*
        | Asynchronous Queue Dispatching
        | Offloads Telegram, Discord, and Webhook notifications to background
        | workers for zero request latency overhead.
        */
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

        /*
        | Native Laravel Email Alert Notifications
        | Dispatches security notifications via Laravel's native mail system
        | using standard SMTP / SES / Resend / Mailgun driver configured in app.
        */
        'mail' => [
            'enabled' => env('SECURITY_MAIL_ENABLED', false),
            'to' => env('SECURITY_ALERT_EMAIL'), // String or array of recipient email addresses
            'subject_prefix' => env('SECURITY_MAIL_SUBJECT_PREFIX', '[SECURITY DEFENSE ALERT]'),
            'timeout' => 10,
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
            // Always run the regex scan even for empty/bodyless requests.
            // Stronger but higher CPU cost at scale — leave false for cheap fast-path.
            'scan_empty_requests' => false,
            'excluded_paths' => [
                // e.g. 'api/webhooks/*'
            ],
        ],

        /*
        | Active Request Flood Protection (DDoS / scraper defense)
        | Cheap per-IP windowed request counter (atomic cache increment, O(1)).
        | An IP exceeding the cap is rejected and eventually auto-quarantined,
        | keeping regex/scan cost near-zero during floods.
        */
        'request_flood' => [
            'enabled' => env('SECURITY_DEFENSE_FLOOD_PROTECTION', true),
            'max_requests_per_second' => 200, // windowed cap per IP
            'window' => 5,                    // seconds per counting window
            'jail_after_exceeding' => 2,      // consecutive windows over cap before auto-jail
        ],

        /*
        | Active IP Quarantine (Fail2Ban-Style Defense)
        | Automatically isolates IPs executing critical attacks or exceeding
        | compound threat score thresholds to cut CPU load during active attacks.
        */
        'quarantine' => [
            'enabled' => env('SECURITY_QUARANTINE_ENABLED', true),
            'duration' => 900,                // Quarantine duration in seconds (15 mins)
            'auto_jail_on_critical' => true,  // Automatically jail on critical threat block
            'response_status' => 429,         // HTTP 429 Too Many Requests
            'response_message' => 'Your IP has been temporarily quarantined due to suspicious security activity.',
            // Durable DB-backed quarantine — survives cache flush / restart / multi-server
            'persist_to_database' => env('SECURITY_QUARANTINE_PERSIST_DB', false),
            'table' => 'security_quarantines',
            'whitelist' => [
                '127.0.0.1',
                '::1',
            ],
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Security Defense Monitoring Dashboard
    |--------------------------------------------------------------------------
    | Dedicated real-time monitoring interface for security posture, threat stats,
    | IP quarantines, and alert channel diagnostic testing.
    | STRICT LOCAL ACCESS: Restricted by default to local environment and localhost.
    */
    'dashboard' => [
        'enabled' => env('SECURITY_DEFENSE_DASHBOARD_ENABLED', true),
        'path' => env('SECURITY_DEFENSE_DASHBOARD_PATH', 'security-defense'),
        'local_only' => env('SECURITY_DEFENSE_DASHBOARD_LOCAL_ONLY', true),
        'allowed_ips' => [
            '127.0.0.1',
            '::1',
        ],
    ],
];
