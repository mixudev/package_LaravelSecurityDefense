<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Master Enable Switch
    |--------------------------------------------------------------------------
    | Globally enables or disables security defense analysis, alerting, and
    | preventive middleware.
    */
    'enabled' => true,

    /*
    |--------------------------------------------------------------------------
    | Cache Store & Prefix
    |--------------------------------------------------------------------------
    | Cache repository used for sliding-window counters, deduplication, and
    | temporary IP quarantine. If null, application default cache is used.
    */
    'cache_store' => null,
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
                'session_fingerprint' => 45,
                'behavioral_velocity' => 35,
                'header_consistency' => 25,
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
                    'eval_based' => true,
                    'php_code_execution' => true,
                    'template_injection' => true,
                    'crlf_injection' => true,
                    'ssrf' => true,
                    // localhost/127.0.0.1 SSRF — OFF by default (host apps legitimately
                    // post to their own origin, e.g. http://localhost:8000/ telemetry).
                    // Set to true only on strict deployments without local loopback traffic.
                    'ssrf_localhost' => false,
                    'xxe' => true,
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
                'block_empty_user_agent' => false, // Block requests with no User-Agent header
                'block_headless_clients' => false, // curl, python-requests, Go-http-client, headless Chrome, etc. (opt-in: may block CI/monitoring)
            ],

            'session_fingerprint' => [
                'enabled' => true,
                'severity' => 'high',
                'session_ttl' => 7200,    // 2 hours window
            ],

            'behavioral_velocity' => [
                'enabled' => true,
                'threshold' => 120,       // Max requests per minute per authenticated user
                'window' => 60,           // 1 minute window
                'severity' => 'high',
            ],

            'header_consistency' => [
                'enabled' => true,
                'severity' => 'medium',
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
            'enabled' => false,
            'connection' => null,
            'queue_name' => 'security-alerts',
        ],

        'database' => [
            'enabled' => true,
            'table' => 'security_alerts',
        ],

        /*
        | Telegram Bot Alerting & Interactive Control Panel
        */
        'telegram' => [
            'enabled' => false,
            'bot_token' => env('SECURITY_TELEGRAM_BOT_TOKEN'),
            'chat_id' => env('SECURITY_TELEGRAM_CHAT_ID'),
            'timeout' => 5,
            'interactive' => [
                'enabled' => false,
            ],
        ],

        'discord' => [
            'enabled' => false,
            'webhook_url' => env('SECURITY_DISCORD_WEBHOOK'),
            'timeout' => 5,
        ],

        'webhook' => [
            'enabled' => false,
            'url' => env('SECURITY_WEBHOOK_URL'),
            'secret' => env('SECURITY_WEBHOOK_SECRET'),
            'timeout' => 5,
        ],

        /*
        | Native Laravel Email Alert Notifications
        | Dispatches security notifications via Laravel's native mail system.
        */
        'mail' => [
            'enabled' => false,
            'to' => env('SECURITY_ALERT_EMAIL'),
            'subject_prefix' => '[SECURITY DEFENSE ALERT]',
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
            'scan_empty_requests' => false,
            'excluded_paths' => [
                // e.g. 'api/webhooks/*'
            ],
        ],

        /*
        | Active Request Flood Protection (DDoS / scraper defense)
        */
        'request_flood' => [
            'enabled' => true,
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
            'enabled' => true,
            'duration' => 900,                // Quarantine duration in seconds (15 mins)
            'auto_jail_on_critical' => true,  // Automatically jail on critical threat block
            'response_status' => 429,         // HTTP 429 Too Many Requests
            'response_message' => 'Your IP has been temporarily quarantined due to suspicious security activity.',
            'persist_to_database' => false,
            // DB lookup failure after cache miss: false avoids blocking clean traffic;
            // true fails closed for deployments where active threat indicators require it.
            'db_fail_closed' => false,
            'table' => 'security_quarantines',
            'whitelist' => [
                '127.0.0.1',
                '::1',
            ],
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Database Change Monitoring & Tamper Intelligence (Audit Trail)
    |--------------------------------------------------------------------------
    | Tracks what data changed, when, by whom, originating URL, method, and
    | request payload snapshot. Detects parameter tampering via Burp Suite.
    */
    'data_audit' => [
        'enabled' => true,
        'table' => 'security_data_audits',
        'alert_on_tampering' => true,

        // Models to automatically watch via service provider without trait
        'auto_watch_models' => [
            // App\Models\User::class,
        ],

        // Columns whose values must be redacted to prevent sensitive data leakage
        'default_masked_fields' => [
            'password',
            'password_hash',
            'remember_token',
            'api_token',
            'secret',
            'two_factor_secret',
            'credit_card',
            'cvv',
        ],

        // Columns excluded from audit recording
        'default_excluded_fields' => [
            'updated_at',
            'created_at',
        ],

        // Critical columns that trigger "TAMPER DETECTED" if modified directly via HTTP payload
        'sensitive_watch_fields' => [
            'is_admin',
            'role',
            'role_id',
            'permissions',
            'balance',
            'credit',
            'status',
            'email_verified_at',
        ],

        // Trap field name for automated form-grabbers / bots (Honeypot)
        'honeypot_field' => '_system_sync_token',

        // Max byte size of request payload snapshot before truncation (Anti-DoS)
        'max_payload_snapshot_bytes' => 8192,

        // Asynchronous queue configuration for zero latency on high-throughput apps
        'queue' => [
            'enabled' => false, // Set to true to process audit logs in background worker
            'connection' => null,
            'queue' => 'security-audit',
        ],

        // Retention in days for security data
        'retention_days' => 30,
        'tampered_retention_days' => 90,
    ],

    /*
    |--------------------------------------------------------------------------
    | Transparent CSP Armor (XSS Defense Behind the Scenes)
    |--------------------------------------------------------------------------
    | Injects strict Content-Security-Policy headers into HTML responses to
    | prevent malicious payload execution even if rendered unescaped.
    */
    'csp_armor' => [
        'enabled' => true,
        'report_only' => false,
        'policy' => null, // null uses default secure policy with nonce
    ],

    /*
    |--------------------------------------------------------------------------
    | Session Intelligence (Post-Authentication Defense)
    |--------------------------------------------------------------------------
    | Protects authenticated sessions against malware infostealers, cookie theft,
    | abnormal post-login velocity, and client header anomalies.
    */
    'session_intelligence' => [
        'enabled' => true,
        'block_on_hijack' => false, // Set to true to immediately abort 403 on critical hijack
    ],

    /*
    |--------------------------------------------------------------------------
    | SIEM Monitoring Dashboard Configuration
    |--------------------------------------------------------------------------
    | Fine-tune dashboard accessibility, caching behavior, rate limiting, and
    | strictness. All settings can be adjusted directly or via .env variables.
    */
    'dashboard' => [
        'enabled' => true,
        'path' => 'security-defense',
        'local_only' => true,
        'allowed_ips' => ['127.0.0.1', '::1'],
        'cache' => [
            'enabled' => true,
            'ttl' => 30,
        ],
        // Dedicated dashboard key (optional). If empty, derived from APP_KEY via HKDF.
        // Rotating this key does NOT affect database encryption or user sessions.
        'key' => env('SECURITY_DEFENSE_KEY', null),
        'rate_limit' => [
            'enabled' => true,
            'max_probes_per_minute' => 30,
        ],
        // Opaque dashboard URL: discovery barrier, never an authenticator.
        // Capability is a one-time, session-bound encrypted+HMAC token derived
        // from APP_KEY (Laravel Crypt). TTL expires it; rotation is implicit.
        'opaque_path' => [
            'enabled' => true,
            // Duration a one-time capability stays valid, in seconds.
            'ttl_seconds' => 60,
        ],
        // Public exposure is opt-in and fail-closed. Prefer VPN/private network.
        'public' => [
            'enabled' => false,
            'authorization_gate' => 'viewSecurityDefenseDashboard',
            'require_authenticated_user' => true,
            'require_step_up' => false,
            'step_up_gate' => null,
            'allowed_ips' => [],
            'allowed_cidrs' => [],
            'rate_limit' => [
                'max_attempts' => 10,
                'decay_seconds' => 60,
            ],
        ],
    ],

    'epistemic' => [
        'enabled' => false,
        'confidence' => ['min' => 0.0, 'max' => 1.0],
        'risk' => ['epsilon' => 0.001, 'max_iterations' => 10, 'decay' => 0.95],
        'graph' => ['max_depth' => 8, 'max_nodes' => 500, 'window_seconds' => 900],
        'limits' => ['max_events' => 500, 'max_evidence' => 500, 'max_metadata_bytes' => 4096],
        'ai' => ['max_evidence' => 20, 'max_metadata_bytes' => 4096, 'allowed_future_seconds' => 60],
        'memory' => ['retention_days' => 30, 'max_patterns' => 10000],
        'policy' => [
            'block_threshold' => 0.85,
            'quarantine_threshold' => 0.70,
            'challenge_threshold' => 0.50,
            'monitor_threshold' => 0.30,
        ],
        // Assessment never enforces responses unless both flags and adapter are opted in.
        'response' => [
            'enabled' => false,
            'adapter' => null,
        ],
    ],
];

