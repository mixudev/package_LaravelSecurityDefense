<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Channels;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Mixudev\SecurityDefense\Contracts\AlertChannel;
use Mixudev\SecurityDefense\Models\SecurityAlert;
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

        // Discord embed color (Decimal)
        $color = match (strtolower($alert->severity)) {
            'critical' => 15158332, // Red
            'high' => 15105570,     // Orange
            'medium' => 16776960,   // Yellow
            default => 3447003,     // Blue
        };

        $fields = [
            [
                'name' => 'Threat Type',
                'value' => '`' . $alert->threat_type . '`',
                'inline' => true,
            ],
            [
                'name' => 'Severity',
                'value' => strtoupper($alert->severity),
                'inline' => true,
            ],
            [
                'name' => 'Rule Identifier',
                'value' => '`' . ($alert->rule_identifier ?: 'unknown') . '`',
                'inline' => true,
            ],
            [
                'name' => 'Fingerprint',
                'value' => '`' . $alert->fingerprint . '`',
                'inline' => false,
            ],
        ];

        if (!empty($alert->metadata)) {
            $metadataJson = json_encode($alert->metadata, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
            if (strlen((string) $metadataJson) > 1000) {
                $metadataJson = substr((string) $metadataJson, 0, 990) . '...';
            }

            $fields[] = [
                'name' => 'Sanitized Metadata',
                'value' => sprintf("```json\n%s\n```", $metadataJson),
                'inline' => false,
            ];
        }

        $payload = [
            'username' => 'Laravel Security Defense',
            'embeds' => [
                [
                    'title' => '🛡️ Security Threat Detected',
                    'color' => $color,
                    'timestamp' => $alert->created_at?->toIso8601String() ?: gmdate('c'),
                    'fields' => $fields,
                    'footer' => [
                        'text' => 'mixudev/security-defense',
                    ],
                ],
            ],
        ];

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
