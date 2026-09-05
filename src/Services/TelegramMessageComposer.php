<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Services;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Mixudev\SecurityDefense\Models\SecurityAlert;
use Mixudev\SecurityDefense\Models\SecurityQuarantine;
use Throwable;

/**
 * Builds Telegram message payloads (text + inline keyboard).
 * Pure composition — no HTTP calls; transport lives in TelegramApiClient.
 */
class TelegramMessageComposer
{
    /**
     * Build Main Menu view payload.
     *
     * @return array{text: string, reply_markup: array<string, mixed>}
     */
    public function buildMainMenu(): array
    {
        $appName = config('app.name', 'Laravel Application');
        $env = app()->environment();
        $time = gmdate('Y-m-d H:i:s') . ' UTC';

        $text = "*=============================*\n"
            . "*SECURITY DEFENSE CONTROL PANEL*\n"
            . "*=============================*\n"
            . "• *Host:* `{$appName}`\n"
            . "• *Environment:* `{$env}`\n"
            . "• *System Time:* `{$time}`\n\n"
            . "Select a diagnostic or monitoring option below:";

        $keyboard = [
            'inline_keyboard' => [
                [
                    ['text' => '[ System Health ]', 'callback_data' => 'sec_health'],
                    ['text' => '[ Security Metrics ]', 'callback_data' => 'sec_metrics'],
                ],
                [
                    ['text' => '[ Recent Incidents ]', 'callback_data' => 'sec_incidents'],
                    ['text' => '[ Quarantined IPs ]', 'callback_data' => 'sec_quarantine'],
                ],
                [
                    ['text' => '[ Refresh Menu ]', 'callback_data' => 'sec_menu'],
                ],
            ],
        ];

        return ['text' => $text, 'reply_markup' => $keyboard];
    }

    /**
     * Build System Health Report payload.
     *
     * @return array{text: string, reply_markup: array<string, mixed>}
     */
    public function buildHealthReport(): array
    {
        // 1. Database check
        $dbStatus = '[FAIL]';
        $dbLatency = 'N/A';
        $dbDriver = config('database.default', 'sqlite');

        try {
            $start = microtime(true);
            DB::connection()->getPdo();
            $dbLatency = sprintf('%.2f ms', (microtime(true) - $start) * 1000);
            $dbStatus = '[OK]';
        } catch (Throwable $e) {
            $dbStatus = '[FAIL: ' . substr($e->getMessage(), 0, 30) . ']';
        }

        // 2. Cache check
        $cacheStatus = '[FAIL]';
        $cacheStore = (string) (config('security-defense.cache_store') ?: config('cache.default', 'file'));

        try {
            $cacheProbeKey = 'sec_defense_health_probe_' . time();
            Cache::store($cacheStore)->put($cacheProbeKey, 1, 10);
            if (Cache::store($cacheStore)->get($cacheProbeKey) === 1) {
                Cache::store($cacheStore)->forget($cacheProbeKey);
                $cacheStatus = '[OK]';
            }
        } catch (Throwable) {
            $cacheStatus = '[FAIL]';
        }

        // 3. Disk space check
        $diskInfo = 'Unavailable';
        try {
            $basePath = function_exists('base_path') ? base_path() : '.';
            $free = @disk_free_space($basePath);
            $total = @disk_total_space($basePath);

            if ($free !== false && $total !== false && $total > 0) {
                $freeGb = sprintf('%.2f', $free / (1024 * 1024 * 1024));
                $totalGb = sprintf('%.2f', $total / (1024 * 1024 * 1024));
                $freePct = sprintf('%.1f%%', ($free / $total) * 100);
                $diskInfo = "{$freeGb} GB free of {$totalGb} GB ({$freePct})";
            }
        } catch (Throwable) {
            $diskInfo = 'N/A';
        }

        // 4. Memory usage
        $memCurrent = sprintf('%.2f MB', memory_get_usage(true) / (1024 * 1024));
        $memPeak = sprintf('%.2f MB', memory_get_peak_usage(true) / (1024 * 1024));

        // 5. Environment & PHP
        $env = app()->environment();
        $debug = config('app.debug') ? 'ENABLED' : 'DISABLED';
        $phpVersion = PHP_VERSION;

        $text = "*=============================*\n"
            . "*SYSTEM HEALTH DIAGNOSTICS*\n"
            . "*=============================*\n"
            . "• *Database:* `{$dbStatus}` {$dbLatency} ({$dbDriver})\n"
            . "• *Cache Store:* `{$cacheStatus}` ({$cacheStore})\n"
            . "• *Storage Free:* `{$diskInfo}`\n"
            . "• *Memory Usage:* `{$memCurrent}` (Peak: `{$memPeak}`)\n"
            . "• *Environment:* `{$env}` (Debug: `{$debug}`)\n"
            . "• *PHP Runtime:* `PHP {$phpVersion}`\n"
            . "• *Timestamp:* `" . gmdate('Y-m-d H:i:s') . " UTC`";

        $keyboard = [
            'inline_keyboard' => [
                [
                    ['text' => '[ Back to Menu ]', 'callback_data' => 'sec_menu'],
                    ['text' => '[ Refresh Health ]', 'callback_data' => 'sec_health'],
                ],
            ],
        ];

        return ['text' => $text, 'reply_markup' => $keyboard];
    }

    /**
     * Build Security Metrics payload.
     *
     * @return array{text: string, reply_markup: array<string, mixed>}
     */
    public function buildSecurityMetrics(): array
    {
        $todayCount = 0;
        $criticalCount = 0;
        $highCount = 0;
        $mediumCount = 0;
        $lowCount = 0;

        try {
            $todayCount = SecurityAlert::query()->where('created_at', '>=', now()->startOfDay())->count();
            $criticalCount = SecurityAlert::query()->where('severity', 'critical')->where('created_at', '>=', now()->startOfDay())->count();
            $highCount = SecurityAlert::query()->where('severity', 'high')->where('created_at', '>=', now()->startOfDay())->count();
            $mediumCount = SecurityAlert::query()->where('severity', 'medium')->where('created_at', '>=', now()->startOfDay())->count();
            $lowCount = SecurityAlert::query()->where('severity', 'low')->where('created_at', '>=', now()->startOfDay())->count();
        } catch (Throwable) {
            // In case database table is not migrated yet
        }

        // Active quarantine count
        $quarantineCount = 0;
        try {
            if (class_exists(SecurityQuarantine::class)) {
                $quarantineCount = SecurityQuarantine::active()->count();
            }
        } catch (Throwable) {
        }

        // Middleware statuses
        $scannerStatus = config('security-defense.middleware.payload_scanner.enabled', true)
            ? 'ACTIVE [' . strtoupper((string) config('security-defense.middleware.payload_scanner.action', 'block')) . ']'
            : 'DISABLED';

        $floodStatus = config('security-defense.middleware.request_flood.enabled', true) ? 'ACTIVE' : 'DISABLED';
        $quarantineStatus = config('security-defense.middleware.quarantine.enabled', true) ? 'ACTIVE' : 'DISABLED';

        $text = "*=============================*\n"
            . "*SECURITY DEFENSE METRICS*\n"
            . "*=============================*\n"
            . "• *Threats Detected (Today):* `{$todayCount}`\n"
            . "  - Critical: `{$criticalCount}`\n"
            . "  - High: `{$highCount}`\n"
            . "  - Medium: `{$mediumCount}`\n"
            . "  - Low: `{$lowCount}`\n\n"
            . "• *Active Quarantines:* `{$quarantineCount}` IP(s)\n\n"
            . "• *Defense Modules:* \n"
            . "  - Payload Scanner: `{$scannerStatus}`\n"
            . "  - Flood Protection: `{$floodStatus}`\n"
            . "  - Auto Quarantine: `{$quarantineStatus}`\n"
            . "• *Timestamp:* `" . gmdate('Y-m-d H:i:s') . " UTC`";

        $keyboard = [
            'inline_keyboard' => [
                [
                    ['text' => '[ Back to Menu ]', 'callback_data' => 'sec_menu'],
                    ['text' => '[ Refresh Metrics ]', 'callback_data' => 'sec_metrics'],
                ],
            ],
        ];

        return ['text' => $text, 'reply_markup' => $keyboard];
    }

    /**
     * Build Recent Security Incidents payload.
     *
     * @return array{text: string, reply_markup: array<string, mixed>}
     */
    public function buildRecentIncidents(): array
    {
        $alerts = [];
        try {
            $alerts = SecurityAlert::query()->orderByDesc('id')->take(5)->get();
        } catch (Throwable) {
        }

        $lines = [
            "*=============================*",
            "*RECENT SECURITY INCIDENTS*",
            "*=============================*",
        ];

        if (empty($alerts) || $alerts->isEmpty()) {
            $lines[] = "• _No security incidents recorded in database._";
        } else {
            foreach ($alerts as $alert) {
                $severity = strtoupper($alert->severity);
                $time = $alert->created_at?->format('Y-m-d H:i:s') ?: 'N/A';
                $ip = $alert->metadata['ip'] ?? 'unknown';

                $lines[] = "• *[{$severity}]* `{$time}`";
                $lines[] = "  Type: `{$alert->threat_type}` | IP: `{$ip}`";
                $lines[] = "  Rule: `{$alert->rule_identifier}`";
            }
        }

        $lines[] = "\n• *Timestamp:* `" . gmdate('Y-m-d H:i:s') . " UTC`";

        $keyboard = [
            'inline_keyboard' => [
                [
                    ['text' => '[ Back to Menu ]', 'callback_data' => 'sec_menu'],
                    ['text' => '[ Refresh Incidents ]', 'callback_data' => 'sec_incidents'],
                ],
            ],
        ];

        return ['text' => implode("\n", $lines), 'reply_markup' => $keyboard];
    }

    /**
     * Build Quarantined IPs Report payload.
     *
     * @return array{text: string, reply_markup: array<string, mixed>}
     */
    public function buildQuarantineReport(): array
    {
        $quarantines = [];
        try {
            if (class_exists(SecurityQuarantine::class)) {
                $quarantines = SecurityQuarantine::active()->orderByDesc('id')->take(10)->get();
            }
        } catch (Throwable) {
        }

        $lines = [
            "*=============================*",
            "*QUARANTINED IP ADDRESSES*",
            "*=============================*",
        ];

        if (empty($quarantines) || $quarantines->isEmpty()) {
            $lines[] = "• _No IP addresses are currently in active quarantine._";
        } else {
            foreach ($quarantines as $item) {
                $remaining = $item->expires_at ? max(0, $item->expires_at->diffInSeconds(now())) : 0;
                $mins = floor($remaining / 60);
                $secs = $remaining % 60;
                $reason = $item->reason ?: 'Suspicious automated activity';

                $lines[] = "• *IP:* `{$item->ip}`";
                $lines[] = "  Expires in: `{$mins}m {$secs}s`";
                $lines[] = "  Reason: `{$reason}`";
            }
        }

        $lines[] = "\n• *Timestamp:* `" . gmdate('Y-m-d H:i:s') . " UTC`";

        $keyboard = [
            'inline_keyboard' => [
                [
                    ['text' => '[ Back to Menu ]', 'callback_data' => 'sec_menu'],
                    ['text' => '[ Refresh Quarantines ]', 'callback_data' => 'sec_quarantine'],
                ],
            ],
        ];

        return ['text' => implode("\n", $lines), 'reply_markup' => $keyboard];
    }

    /**
     * Build help message text.
     */
    public function buildHelpMessage(): string
    {
        return "*SECURITY DEFENSE BOT COMMANDS*\n"
            . "───────────────────────────────\n"
            . "• `/start` or `/menu` - Open interactive control panel\n"
            . "• `/health` - Inspect system diagnostics & latency\n"
            . "• `/metrics` - View 24h security threat posture\n"
            . "• `/incidents` - List latest security alert records\n"
            . "• `/quarantine` - View currently isolated IP addresses\n"
            . "• `/help` - Show this command reference";
    }
}