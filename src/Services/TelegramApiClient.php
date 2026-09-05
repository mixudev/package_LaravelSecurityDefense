<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Services;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Throwable;

/**
 * Thin transport client for the Telegram Bot API.
 * Handles raw HTTP calls only; message composition lives in TelegramMessageComposer
 * and orchestration in TelegramBotService.
 */
class TelegramApiClient
{
    /**
     * Get the configured Telegram Bot Token.
     */
    public function getBotToken(): ?string
    {
        $token = config('security-defense.alerts.telegram.bot_token');

        return is_string($token) && filled($token) ? $token : null;
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