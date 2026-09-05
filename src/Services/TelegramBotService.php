<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Services;

use Illuminate\Support\Facades\Log;

/**
 * Interactive Telegram Bot control panel orchestrator.
 * Routes incoming updates to command handlers; delegates raw Bot API transport
 * to TelegramApiClient and message payload composition to TelegramMessageComposer.
 */
class TelegramBotService
{
    public function __construct(
        protected TelegramApiClient $api,
        protected TelegramMessageComposer $composer,
        protected ?IpQuarantineService $quarantineService = null
    ) {
    }

    /**
     * Get the configured Telegram Bot Token.
     */
    public function getBotToken(): ?string
    {
        return $this->api->getBotToken();
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
        return $this->api->registerBotCommands();
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

            $this->api->sendMessage(
                $chatId,
                "[SECURITY DEFENSE]\nAccess Denied: Chat ID `{$chatId}` is not authorized to access system diagnostics."
            );

            return false;
        }

        return match ($text) {
            '/start', '/menu' => $this->sendMainMenu($chatId),
            '/health' => $this->sendHealthReport($chatId),
            '/metrics' => $this->sendSecurityMetrics($chatId),
            '/incidents' => $this->sendRecentIncidents($chatId),
            '/quarantine' => $this->sendQuarantineReport($chatId),
            '/help' => $this->api->sendMessage($chatId, $this->composer->buildHelpMessage()),
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
            $this->api->answerCallbackQuery($callbackId, 'Access Denied.');

            return false;
        }

        $this->api->answerCallbackQuery($callbackId);

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
        $payload = $this->composer->buildMainMenu();

        return $this->sendOrEditMessage($chatId, $messageId, $payload['text'], $payload['reply_markup']);
    }

    /**
     * Send or edit message with the System Health Report.
     */
    public function sendHealthReport(string|int $chatId, ?int $messageId = null): bool
    {
        $payload = $this->composer->buildHealthReport();

        return $this->sendOrEditMessage($chatId, $messageId, $payload['text'], $payload['reply_markup']);
    }

    /**
     * Send or edit message with Security Defense Metrics.
     */
    public function sendSecurityMetrics(string|int $chatId, ?int $messageId = null): bool
    {
        $payload = $this->composer->buildSecurityMetrics();

        return $this->sendOrEditMessage($chatId, $messageId, $payload['text'], $payload['reply_markup']);
    }

    /**
     * Send or edit message with Recent Security Incidents.
     */
    public function sendRecentIncidents(string|int $chatId, ?int $messageId = null): bool
    {
        $payload = $this->composer->buildRecentIncidents();

        return $this->sendOrEditMessage($chatId, $messageId, $payload['text'], $payload['reply_markup']);
    }

    /**
     * Send or edit message with Active Quarantined IPs.
     */
    public function sendQuarantineReport(string|int $chatId, ?int $messageId = null): bool
    {
        $payload = $this->composer->buildQuarantineReport();

        return $this->sendOrEditMessage($chatId, $messageId, $payload['text'], $payload['reply_markup']);
    }

    /**
     * Send help message with command references.
     */
    public function sendHelpMessage(string|int $chatId): bool
    {
        return $this->api->sendMessage($chatId, $this->composer->buildHelpMessage());
    }

    /**
     * Build Main Menu view payload.
     *
     * @return array{text: string, reply_markup: array<string, mixed>}
     */
    public function buildMainMenu(): array
    {
        return $this->composer->buildMainMenu();
    }

    /**
     * Build System Health Report payload.
     *
     * @return array{text: string, reply_markup: array<string, mixed>}
     */
    public function buildHealthReport(): array
    {
        return $this->composer->buildHealthReport();
    }

    /**
     * Build Security Metrics payload.
     *
     * @return array{text: string, reply_markup: array<string, mixed>}
     */
    public function buildSecurityMetrics(): array
    {
        return $this->composer->buildSecurityMetrics();
    }

    /**
     * Build Recent Security Incidents payload.
     *
     * @return array{text: string, reply_markup: array<string, mixed>}
     */
    public function buildRecentIncidents(): array
    {
        return $this->composer->buildRecentIncidents();
    }

    /**
     * Build Quarantined IPs Report payload.
     *
     * @return array{text: string, reply_markup: array<string, mixed>}
     */
    public function buildQuarantineReport(): array
    {
        return $this->composer->buildQuarantineReport();
    }

    /**
     * Send a new Telegram message via Bot API (legacy public transport API).
     */
    public function sendMessage(string|int $chatId, string $text, ?array $replyMarkup = null): bool
    {
        return $this->api->sendMessage($chatId, $text, $replyMarkup);
    }

    /**
     * Edit an existing Telegram message in place (legacy public transport API).
     */
    public function editMessageText(string|int $chatId, int $messageId, string $text, ?array $replyMarkup = null): bool
    {
        return $this->api->editMessageText($chatId, $messageId, $text, $replyMarkup);
    }

    /**
     * Acknowledge a Telegram callback query to dismiss button loading spinner.
     */
    public function answerCallbackQuery(string $callbackQueryId, ?string $text = null): bool
    {
        return $this->api->answerCallbackQuery($callbackQueryId, $text);
    }

    /**
     * Fetch pending updates from Telegram Bot API via long-polling (getUpdates).
     *
     * @return array<int, array<string, mixed>>
     */
    public function getUpdates(int $offset = 0, int $timeout = 30): array
    {
        return $this->api->getUpdates($offset, $timeout);
    }

    /**
     * Send or edit message smoothly.
     */
    protected function sendOrEditMessage(string|int $chatId, ?int $messageId, string $text, ?array $replyMarkup = null): bool
    {
        if ($messageId !== null) {
            $edited = $this->api->editMessageText($chatId, $messageId, $text, $replyMarkup);
            if ($edited) {
                return true;
            }
        }

        return $this->api->sendMessage($chatId, $text, $replyMarkup);
    }
}