<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Services;

use Exception;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Mixudev\SecurityDefense\Models\SecurityAlert;
use Mixudev\SecurityDefense\Models\SecurityQuarantine;
use Throwable;

/**
 * Service providing interactive Telegram Bot control panel, system health checks,
 * security metrics, incident inspection, and long-polling / webhook processing.
 */
class TelegramBotService
{
    public function __construct(
        protected ?IpQuarantineService $quarantineService = null
    ) {
    }

    /**
     * Get the configured Telegram Bot Token.
     */
    public function getBotToken(): ?string
    {
        $token = config('security-defense.alerts.telegram.bot_token');

        return is_string($token) && filled($token) ? $token : null;
    }

    /**
     * Check if interactive Telegram Bot feature is enabled and configured.
     */
    public function isInteractiveEnabled(): bool
    {
        $telegramEnabled = (bool) config('security-defense.alerts.telegram.enabled', false);
        $interactiveEnabled = (bool) config('security-defense.alerts.telegram.interactive.enabled', true);

        return $telegramEnabled && $interactiveEnabled && $this->getBotToken() !== null;
    }

    /**
     * Automatically derive a deterministic webhook secret from the bot token.
     * Secures incoming webhooks without requiring manual .env configuration.
     */
    public function getWebhookSecret(): ?string
    {
        $token = $this->getBotToken();
        if (!$token) {
            return null;
        }

        return substr(hash('sha256', 'sec_telegram_webhook:' . $token), 0, 32);
    }

    /**
     * Register bot commands with Telegram API so the native "Menu" button
     * appears at the bottom left of the chat in Telegram apps.
     */
    public function registerBotCommands(): bool
    {
        $botToken = $this->getBotToken();
        if (!$botToken) {
            return false;
        }

        $commands = [
            ['command' => 'menu', 'description' => 'Interactive security dashboard'],
            ['command' => 'health', 'description' => 'System health & diagnostics'],
            ['command' => 'metrics', 'description' => 'Security threats & defense metrics'],
            ['command' => 'incidents', 'description' => 'Latest security alert logs'],
            ['command' => 'quarantine', 'description' => 'Active quarantined IP addresses'],
            ['command' => 'help', 'description' => 'Command reference & usage guide'],
        ];

        try {
            $response = Http::timeout(5)->post(
                sprintf('https://api.telegram.org/bot%s/setMyCommands', $botToken),
                ['commands' => $commands]
            );

            return $response->successful();
        } catch (Throwable $e) {
            Log::warning('SecurityDefense: Failed to register Telegram bot commands.', ['error' => $e->getMessage()]);
            return false;
        }
    }

    /**
     * Determine whether the given chat ID is authorized to interact with the bot.
     */
    public function isAuthorized(string|int $chatId): bool
    {
        $primaryChatId = (string) config('security-defense.alerts.telegram.chat_id', '');

        return filled($primaryChatId) && (string) $chatId === $primaryChatId;
    }

    /**
     * Process an incoming Telegram update payload (from Webhook or Long-Polling).
     *
     * @param array<string, mixed> $update
     */
    public function handleUpdate(array $update): bool
    {
        if (isset($update['callback_query'])) {
            return $this->handleCallbackQuery($update['callback_query']);
        }

        if (isset($update['message'])) {
            return $this->handleMessage($update['message']);
        }

        return false;
    }

    /**
     * Handle incoming text message or command.
     *
     * @param array<string, mixed> $message
     */
    protected function handleMessage(array $message): bool
    {
        $chatId = $message['chat']['id'] ?? null;
        $text = trim((string) ($message['text'] ?? ''));

        if ($chatId === null) {
            return false;
        }

        if (!$this->isAuthorized($chatId)) {
            Log::warning('SecurityDefense: Unauthorized Telegram interaction attempted.', [
                'chat_id' => $chatId,
                'text' => $text,
            ]);

            $this->sendMessage(
                $chatId,
                "[SECURITY DEFENSE]\nAccess Denied: Chat ID `{$chatId}` is not authorized to access system diagnostics."
            );

            return false;
        }

        // Extract command (handles '/command' or '/command@botname')
        $command = strtolower(explode(' ', explode('@', $text)[0])[0]);

        return match ($command) {
            '/start', '/menu' => $this->sendMainMenu($chatId),
            '/health' => $this->sendHealthReport($chatId),
            '/metrics', '/status' => $this->sendSecurityMetrics($chatId),
            '/incidents', '/alerts' => $this->sendRecentIncidents($chatId),
            '/quarantine', '/quarantines' => $this->sendQuarantineReport($chatId),
            '/help' => $this->sendHelpMessage($chatId),
            default => $this->sendMainMenu($chatId),
        };
    }

    /**
     * Handle callback query from inline keyboard button click.
     *
     * @param array<string, mixed> $callbackQuery
     */
    protected function handleCallbackQuery(array $callbackQuery): bool
    {
        $callbackId = (string) ($callbackQuery['id'] ?? '');
        $data = (string) ($callbackQuery['data'] ?? '');
        $message = $callbackQuery['message'] ?? [];
        $chatId = $message['chat']['id'] ?? ($callbackQuery['from']['id'] ?? null);
        $messageId = $message['message_id'] ?? null;

        if ($chatId === null) {
            return false;
        }

        if (!$this->isAuthorized($chatId)) {
            $this->answerCallbackQuery($callbackId, 'Access Denied.');
            return false;
        }

        $this->answerCallbackQuery($callbackId);

        return match ($data) {
            'sec_menu' => $this->sendMainMenu($chatId, $messageId),
            'sec_health' => $this->sendHealthReport($chatId, $messageId),
            'sec_metrics' => $this->sendSecurityMetrics($chatId, $messageId),
            'sec_incidents' => $this->sendRecentIncidents($chatId, $messageId),
            'sec_quarantine' => $this->sendQuarantineReport($chatId, $messageId),
            default => $this->sendMainMenu($chatId, $messageId),
        };
    }

    /**
     * Send or edit message with the Main Menu.
     */
    public function sendMainMenu(string|int $chatId, ?int $messageId = null): bool
    {
        $payload = $this->buildMainMenu();

        return $this->sendOrEditMessage($chatId, $messageId, $payload['text'], $payload['reply_markup']);
    }

    /**
     * Send or edit message with the System Health Report.
     */
    public function sendHealthReport(string|int $chatId, ?int $messageId = null): bool
    {
        $payload = $this->buildHealthReport();

        return $this->sendOrEditMessage($chatId, $messageId, $payload['text'], $payload['reply_markup']);
    }

    /**
     * Send or edit message with Security Defense Metrics.
     */
    public function sendSecurityMetrics(string|int $chatId, ?int $messageId = null): bool
    {
        $payload = $this->buildSecurityMetrics();

        return $this->sendOrEditMessage($chatId, $messageId, $payload['text'], $payload['reply_markup']);
    }

    /**
     * Send or edit message with Recent Security Incidents.
     */
    public function sendRecentIncidents(string|int $chatId, ?int $messageId = null): bool
    {
        $payload = $this->buildRecentIncidents();

        return $this->sendOrEditMessage($chatId, $messageId, $payload['text'], $payload['reply_markup']);
    }

    /**
     * Send or edit message with Active Quarantined IPs.
     */
    public function sendQuarantineReport(string|int $chatId, ?int $messageId = null): bool
    {
        $payload = $this->buildQuarantineReport();

        return $this->sendOrEditMessage($chatId, $messageId, $payload['text'], $payload['reply_markup']);
    }

    /**
     * Send help message with command references.
     */
    public function sendHelpMessage(string|int $chatId): bool
    {
        $text = "*SECURITY DEFENSE BOT COMMANDS*\n"
            . "───────────────────────────────\n"
            . "• `/start` or `/menu` - Open interactive control panel\n"
            . "• `/health` - Inspect system diagnostics & latency\n"
            . "• `/metrics` - View 24h security threat posture\n"
            . "• `/incidents` - List latest security alert records\n"
            . "• `/quarantine` - View currently isolated IP addresses\n"
            . "• `/help` - Show this command reference";

        return $this->sendMessage($chatId, $text);
    }

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
     * Send or edit message smoothly.
     */
    protected function sendOrEditMessage(string|int $chatId, ?int $messageId, string $text, ?array $replyMarkup = null): bool
    {
        if ($messageId !== null) {
            $edited = $this->editMessageText($chatId, $messageId, $text, $replyMarkup);
            if ($edited) {
                return true;
            }
        }

        return $this->sendMessage($chatId, $text, $replyMarkup);
    }

    /**
     * Send a new Telegram message via Bot API.
     */
    public function sendMessage(string|int $chatId, string $text, ?array $replyMarkup = null): bool
    {
        $botToken = $this->getBotToken();
        if (!$botToken) {
            return false;
        }

        $timeout = (int) config('security-defense.alerts.telegram.timeout', 5);

        $params = [
            'chat_id' => $chatId,
            'text' => $text,
            'parse_mode' => 'Markdown',
            'disable_web_page_preview' => true,
        ];

        if ($replyMarkup !== null) {
            $params['reply_markup'] = json_encode($replyMarkup);
        }

        try {
            $response = Http::timeout($timeout)->post(
                sprintf('https://api.telegram.org/bot%s/sendMessage', $botToken),
                $params
            );

            return $response->successful();
        } catch (Throwable $e) {
            Log::warning('SecurityDefense: Failed to dispatch Telegram message.', [
                'error' => $e->getMessage(),
            ]);
            return false;
        }
    }

    /**
     * Edit an existing Telegram message in place.
     */
    public function editMessageText(string|int $chatId, int $messageId, string $text, ?array $replyMarkup = null): bool
    {
        $botToken = $this->getBotToken();
        if (!$botToken) {
            return false;
        }

        $timeout = (int) config('security-defense.alerts.telegram.timeout', 5);

        $params = [
            'chat_id' => $chatId,
            'message_id' => $messageId,
            'text' => $text,
            'parse_mode' => 'Markdown',
            'disable_web_page_preview' => true,
        ];

        if ($replyMarkup !== null) {
            $params['reply_markup'] = json_encode($replyMarkup);
        }

        try {
            $response = Http::timeout($timeout)->post(
                sprintf('https://api.telegram.org/bot%s/editMessageText', $botToken),
                $params
            );

            return $response->successful();
        } catch (Throwable $e) {
            Log::debug('SecurityDefense: Edit message skipped or failed.', [
                'error' => $e->getMessage(),
            ]);
            return false;
        }
    }

    /**
     * Acknowledge a Telegram callback query to dismiss button loading spinner.
     */
    public function answerCallbackQuery(string $callbackQueryId, ?string $text = null): bool
    {
        $botToken = $this->getBotToken();
        if (!$botToken || empty($callbackQueryId)) {
            return false;
        }

        $timeout = (int) config('security-defense.alerts.telegram.timeout', 5);

        $params = [
            'callback_query_id' => $callbackQueryId,
        ];

        if ($text !== null) {
            $params['text'] = $text;
        }

        try {
            $response = Http::timeout($timeout)->post(
                sprintf('https://api.telegram.org/bot%s/answerCallbackQuery', $botToken),
                $params
            );

            return $response->successful();
        } catch (Throwable) {
            return false;
        }
    }

    /**
     * Fetch pending updates from Telegram Bot API via long-polling (getUpdates).
     *
     * @return array<int, array<string, mixed>>
     */
    public function getUpdates(int $offset = 0, int $timeout = 30): array
    {
        $botToken = $this->getBotToken();
        if (!$botToken) {
            return [];
        }

        try {
            $response = Http::timeout($timeout + 5)->get(
                sprintf('https://api.telegram.org/bot%s/getUpdates', $botToken),
                [
                    'offset' => $offset,
                    'timeout' => $timeout,
                    'allowed_updates' => json_encode(['message', 'callback_query']),
                ]
            );

            if ($response->successful() && isset($response->json()['result'])) {
                return (array) $response->json()['result'];
            }

            return [];
        } catch (Throwable $e) {
            Log::debug('SecurityDefense: getUpdates call failed.', ['error' => $e->getMessage()]);
            return [];
        }
    }
}
