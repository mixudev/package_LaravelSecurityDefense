<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Services;

use InvalidArgumentException;
use Mixudev\SecurityDefense\Contracts\AlertChannel;
use Mixudev\SecurityDefense\Models\SecurityAlert;

/**
 * Service for securely testing alert channel connectivity and webhook deliveries.
 * Hardened with channel whitelisting, non-destructive test alerts, and detailed diagnostics.
 */
class ChannelTestService
{
    /**
     * Whitelist of testable external notification channels.
     *
     * @var array<string>
     */
    protected const ALLOWED_CHANNELS = [
        'webhook',
        'discord',
        'telegram',
        'mail',
        'database',
    ];

    public function __construct(
        protected AlertDispatcher $dispatcher
    ) {}

    /**
     * Test a specific alert channel.
     *
     * @param string $identifier
     * @return array{channel: string, success: bool, enabled: bool, configured: bool, latency_ms?: float, message: string}
     */
    public function testChannel(string $identifier): array
    {
        $identifier = strtolower(trim($identifier));

        if (!in_array($identifier, self::ALLOWED_CHANNELS, true)) {
            throw new InvalidArgumentException("Invalid channel [{$identifier}]. Allowed channels: " . implode(', ', self::ALLOWED_CHANNELS));
        }

        $channels = $this->dispatcher->getChannels();
        $channel = $channels[$identifier] ?? null;

        if (!$channel instanceof AlertChannel) {
            return [
                'channel' => $identifier,
                'success' => false,
                'enabled' => false,
                'configured' => false,
                'message' => "Channel [{$identifier}] is not registered in the alert dispatcher.",
            ];
        }

        if (!$channel->isEnabled()) {
            return [
                'channel' => $identifier,
                'success' => false,
                'enabled' => false,
                'configured' => $channel->isConfigured(),
                'message' => "Channel [{$identifier}] is disabled in configuration.",
            ];
        }

        if (!$channel->isConfigured()) {
            return [
                'channel' => $identifier,
                'success' => false,
                'enabled' => true,
                'configured' => false,
                'message' => "Channel [{$identifier}] is enabled but missing required credentials or configuration.",
            ];
        }

        // Create transient diagnostic SecurityAlert
        $alert = new SecurityAlert([
            'severity' => SecurityAlert::SEVERITY_LOW,
            'threat_type' => 'channel_connectivity_test',
            'fingerprint' => 'test_probe_' . substr(sha1(uniqid((string) mt_rand(), true)), 0, 16),
            'status' => SecurityAlert::STATUS_NEW,
            'rule_identifier' => 'manual_diagnostic_probe',
            'metadata' => [
                '_is_test' => true,
                'channel' => $identifier,
                'source' => 'security_defense_testing_suite',
                'dispatched_at' => now()->toIso8601String(),
                'ip' => '127.0.0.1',
            ],
        ]);

        $startTime = microtime(true);
        $delivered = $channel->send($alert);
        $latencyMs = round((microtime(true) - $startTime) * 1000, 2);

        return [
            'channel' => $identifier,
            'success' => $delivered,
            'enabled' => true,
            'configured' => true,
            'latency_ms' => $latencyMs,
            'message' => $delivered
                ? "Test probe delivered successfully to [{$identifier}] ({$latencyMs}ms)."
                : "Failed delivering test probe to [{$identifier}]. Check logs for details.",
        ];
    }

    /**
     * Test all available channels or all enabled channels.
     *
     * @param bool $onlyConfigured If true, tests only channels that are enabled and configured
     * @return array<string, array{channel: string, success: bool, enabled: bool, configured: bool, latency_ms?: float, message: string}>
     */
    public function testAll(bool $onlyConfigured = false): array
    {
        $results = [];
        $channels = $this->dispatcher->getChannels();

        foreach (self::ALLOWED_CHANNELS as $identifier) {
            $channel = $channels[$identifier] ?? null;

            if ($onlyConfigured && ($channel === null || !$channel->isEnabled() || !$channel->isConfigured())) {
                continue;
            }

            $results[$identifier] = $this->testChannel($identifier);
        }

        return $results;
    }

    /**
     * Get real-time health and configuration status of all channels.
     *
     * @return array<string, array{identifier: string, enabled: bool, configured: bool, target?: string}>
     */
    public function getChannelsStatus(): array
    {
        $statuses = [];
        $channels = $this->dispatcher->getChannels();

        foreach (self::ALLOWED_CHANNELS as $identifier) {
            $channel = $channels[$identifier] ?? null;

            $enabled = $channel ? $channel->isEnabled() : false;
            $configured = $channel ? $channel->isConfigured() : false;

            $target = match ($identifier) {
                'webhook' => (string) config('security-defense.alerts.webhook.url', 'Not Set'),
                'discord' => (string) config('security-defense.alerts.discord.webhook_url', 'Not Set'),
                'telegram' => (string) config('security-defense.alerts.telegram.chat_id', 'Not Set'),
                'mail' => is_array(config('security-defense.alerts.mail.to')) ? implode(', ', config('security-defense.alerts.mail.to')) : (string) (config('security-defense.alerts.mail.to') ?: 'Not Set'),
                'database' => (string) config('security-defense.alerts.database.table', 'security_alerts'),
                default => 'Local',
            };

            // Mask sensitive parts of target
            if ($identifier === 'discord' || $identifier === 'webhook') {
                if (strlen($target) > 35) {
                    $target = substr($target, 0, 22) . '...' . substr($target, -8);
                }
            }

            $statuses[$identifier] = [
                'identifier' => $identifier,
                'enabled' => $enabled,
                'configured' => $configured,
                'target' => $target,
            ];
        }

        return $statuses;
    }
}
