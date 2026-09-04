<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Channels;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Mixudev\SecurityDefense\Contracts\AlertChannel;
use Mixudev\SecurityDefense\Models\SecurityAlert;
use Mixudev\SecurityDefense\Support\DiscordAlertFormatter;
use Throwable;

/**
 * Optional Discord alert channel sending notifications via Webhook.
 */
class DiscordChannel implements AlertChannel
{
    public function identifier(): string
    {
        return 'discord';
    }

    public function isEnabled(): bool
    {
        return (bool) config('security-defense.alerts.discord.enabled', false);
    }

    public function isConfigured(): bool
    {
        $webhookUrl = config('security-defense.alerts.discord.webhook_url');

        return !empty($webhookUrl) && is_string($webhookUrl);
    }

    /**
     * Send alert embed to Discord Webhook.
     */
    public function send(SecurityAlert $alert): bool
    {
        if (!$this->isEnabled() || !$this->isConfigured()) {
            return false;
        }

        $webhookUrl = (string) config('security-defense.alerts.discord.webhook_url');
        $timeout = (int) config('security-defense.alerts.discord.timeout', 5);

        $payload = DiscordAlertFormatter::payload($alert);

        try {
            $response = Http::timeout($timeout)->post($webhookUrl, $payload);

            if (!$response->successful()) {
                Log::warning('SecurityDefense: Failed to send Discord alert.', [
                    'status' => $response->status(),
                    'response' => $response->body(),
                ]);
                return false;
            }

            return true;
        } catch (Throwable $e) {
            Log::warning('SecurityDefense: Exception occurred while sending Discord alert.', [
                'error' => $e->getMessage(),
            ]);
            return false;
        }
    }
}
