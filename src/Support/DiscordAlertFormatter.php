<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Support;

use Mixudev\SecurityDefense\Models\SecurityAlert;

/**
 * Builds a maintainable, professional Discord webhook embed payload from a
 * SecurityAlert. Centralizes the embed structure (title, fields, color, footer)
 * so the DiscordChannel only handles transport.
 */
final class DiscordAlertFormatter
{
    /**
     * Discord embed color codes (decimal) per severity.
     *
     * @var array<string, int>
     */
    protected const SEVERITY_COLORS = [
        'critical' => 15158332, // Red (#EE0000)
        'high'     => 15105570, // Orange (#FF8000)
        'medium'   => 16776960, // Yellow (#FFFF00)
        'low'      => 3447003,  // Blue (#3498DB)
    ];

    /**
     * Build the full webhook payload for a single alert.
     *
     * @param SecurityAlert $alert
     * @return array<string, mixed>
     */
    public static function payload(SecurityAlert $alert): array
    {
        $isTest = !empty($alert->metadata['_is_test'] ?? null);

        $embed = [
            'title' => $isTest ? 'Channel Connectivity Test' : 'Security Threat Detected',
            'description' => self::description($alert),
            'color' => self::severityColor($alert->severity),
            'timestamp' => $alert->created_at?->toIso8601String() ?: gmdate('c'),
            'fields' => self::fields($alert),
            'footer' => [
                'text' => empty($alert->rule_identifier)
                    ? config('app.name', 'Laravel Application')
                    : sprintf('%s • %s', config('app.name', 'Laravel Application'), $alert->rule_identifier),
            ],
        ];

        return [
            'username' => 'Laravel Security Defense',
            'embeds' => [$embed],
        ];
    }

    /**
     * Human-readable description line for the embed.
     */
    protected static function description(SecurityAlert $alert): string
    {
        $threat = ucwords(str_replace('_', ' ', $alert->threat_type));

        if (!empty($alert->metadata['_is_test'] ?? null)) {
            $source = $alert->metadata['source'] ?? 'automated';
            return sprintf('Connectivity probe for `%s` was delivered successfully.', e($source));
        }

        return sprintf(
            'A **%s** severity threat was detected: **%s**.',
            strtoupper($alert->severity),
            e($threat)
        );
    }

    /**
     * Build the embed fields array.
     *
     * @return array<int, array{name: string, value: string, inline: bool}>
     */
    protected static function fields(SecurityAlert $alert): array
    {
        $fields = [
            ['name' => 'Threat Type', 'value' => '`' . $alert->threat_type . '`', 'inline' => true],
            ['name' => 'Severity', 'value' => strtoupper($alert->severity), 'inline' => true],
            ['name' => 'Rule', 'value' => '`' . ($alert->rule_identifier ?: 'unknown') . '`', 'inline' => true],
        ];

        if (filled($alert->fingerprint)) {
            $fields[] = ['name' => 'Fingerprint', 'value' => '`' . $alert->fingerprint . '`', 'inline' => false];
        }

        $metadata = $alert->metadata ?? [];
        // Strip internal diagnostic keys from the exposed metadata block
        unset($metadata['_is_test'], $metadata['source']);

        if (!empty($metadata)) {
            $json = (string) json_encode($metadata, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
            $json = str_replace('```', "'''", $json);
            if (strlen($json) > 1000) {
                $json = substr($json, 0, 980) . '...[TRUNCATED]';
            }

            $fields[] = [
                'name' => 'Sanitized Telemetry',
                'value' => sprintf("```json\n%s\n```", $json),
                'inline' => false,
            ];
        }

        return $fields;
    }

    /**
     * Resolve the Discord embed color for a severity, falling back to blue.
     */
    protected static function severityColor(string $severity): int
    {
        return self::SEVERITY_COLORS[strtolower($severity)] ?? self::SEVERITY_COLORS['low'];
    }
}
