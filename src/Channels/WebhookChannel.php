<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Channels;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Mixudev\SecurityDefense\Contracts\AlertChannel;
use Mixudev\SecurityDefense\Models\SecurityAlert;
use Throwable;

/**
 * Extensible Webhook alert channel for SIEM/SOC, central dashboards, or custom API endpoints.
 */
class WebhookChannel implements AlertChannel
{
    public function identifier(): string
    {
        return 'webhook';
    }

    public function isEnabled(): bool
    {
        return (bool) config('security-defense.alerts.webhook.enabled', false);
    }

    public function isConfigured(): bool
    {
        $url = config('security-defense.alerts.webhook.url');

        return !empty($url) && is_string($url);
    }

    /**
     * Send alert payload to external webhook / SIEM receiver.
     */
    public function send(SecurityAlert $alert): bool
    {
        if (!$this->isEnabled() || !$this->isConfigured()) {
            return false;
        }

        $url = (string) config('security-defense.alerts.webhook.url');
        $secret = config('security-defense.alerts.webhook.secret');
        $timeout = (int) config('security-defense.alerts.webhook.timeout', 5);

        $payload = [
            'event' => 'security_alert',
            'alert_id' => $alert->id,
            'severity' => $alert->severity,
            'threat_type' => $alert->threat_type,
            'fingerprint' => $alert->fingerprint,
            'status' => $alert->status,
            'rule_identifier' => $alert->rule_identifier,
            'metadata' => $alert->metadata ?? [],
            'created_at' => $alert->created_at?->toIso8601String() ?: gmdate('c'),
        ];

        $jsonPayload = (string) json_encode($payload);

        $headers = [
            'Content-Type' => 'application/json',
            'User-Agent' => 'mixudev-security-defense/1.0',
        ];

        if (!empty($secret) && is_string($secret)) {
            $headers['X-Security-Defense-Signature'] = hash_hmac('sha256', $jsonPayload, $secret);
        }

        try {
            $response = Http::timeout($timeout)
                ->withHeaders($headers)
                ->withBody($jsonPayload, 'application/json')
                ->post($url);

            if (!$response->successful()) {
                Log::warning('SecurityDefense: Webhook alert delivery returned non-2xx response.', [
                    'url' => $this->redactUrl($url),
                    'status' => $response->status(),
                ]);
                return false;
            }

            return true;
        } catch (Throwable $e) {
            Log::warning('SecurityDefense: Exception occurred while sending Webhook alert.', [
                'url' => $this->redactUrl($url),
            ]);
            return false;
        }
    }

    /**
     * Strip query string and credentials from a URL before logging.
     */
    protected function redactUrl(string $url): string
    {
        $parsed = parse_url($url);
        if ($parsed === false) {
            return '[invalid-url]';
        }

        $scheme = $parsed['scheme'] ?? '';
        $host = $parsed['host'] ?? '';
        $port = isset($parsed['port']) ? ':' . $parsed['port'] : '';
        $path = $parsed['path'] ?? '';

        return sprintf('%s://%s%s%s', $scheme, $host, $port, $path);
    }
}
