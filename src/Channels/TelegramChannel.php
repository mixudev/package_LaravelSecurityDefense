<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Channels;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Mixudev\SecurityDefense\Contracts\AlertChannel;
use Mixudev\SecurityDefense\Models\SecurityAlert;
use Mixudev\SecurityDefense\Support\TelegramAlertFormatter;
use Throwable;

/**
 * Optional Telegram alert channel sending notifications via Telegram Bot API.
 */
class TelegramChannel implements AlertChannel
{
    public function identifier(): string
    {
        return 'telegram';
    }

    public function isEnabled(): bool
    {
        return (bool) config('security-defense.alerts.telegram.enabled', false);
    }

    public function isConfigured(): bool
    {
        $botToken = config('security-defense.alerts.telegram.bot_token');
        $chatId = config('security-defense.alerts.telegram.chat_id');

        return !empty($botToken) && !empty($chatId);
    }

    /**
     * Send alert message to Telegram chat.
     */
    public function send(SecurityAlert $alert): bool
    {
        if (!$this->isEnabled() || !$this->isConfigured()) {
            return false;
        }

        $botToken = (string) config('security-defense.alerts.telegram.bot_token');
        $chatId = (string) config('security-defense.alerts.telegram.chat_id');
        $timeout = (int) config('security-defense.alerts.telegram.timeout', 5);

        $message = TelegramAlertFormatter::message($alert);

        try {
            $response = Http::timeout($timeout)->post(
                sprintf('https://api.telegram.org/bot%s/sendMessage', $botToken),
                [
                    'chat_id' => $chatId,
                    'text' => $message,
                    'parse_mode' => 'Markdown',
                    'disable_web_page_preview' => true,
                ]
            );

            if (!$response->successful()) {
                // If Telegram rejected markdown parsing (400 Bad Request), fallback to plain text
                if ($response->status() === 400) {
                    $plainText = strip_tags(str_replace(['*', '`'], '', $message));
                    $fallback = Http::timeout($timeout)->post(
                        sprintf('https://api.telegram.org/bot%s/sendMessage', $botToken),
                        [
                            'chat_id' => $chatId,
                            'text' => $plainText,
                            'disable_web_page_preview' => true,
                        ]
                    );

                    if ($fallback->successful()) {
                        return true;
                    }
                }

                Log::warning('SecurityDefense: Failed to send Telegram alert.', [
                    'status' => $response->status(),
                    'response' => $response->body(),
                ]);
                return false;
            }

            return true;
        } catch (Throwable $e) {
            Log::warning('SecurityDefense: Exception occurred while sending Telegram alert.', [
                'error' => $e->getMessage(),
            ]);
            return false;
        }
    }
}
