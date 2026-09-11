<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Support;

use Mixudev\SecurityDefense\Models\SecurityAlert;

/**
 * Builds a maintainable, professional Telegram message (Markdown) from a
 * SecurityAlert. Centralizes formatting so TelegramChannel only handles transport.
 */
final class TelegramAlertFormatter
{
    /**
     * Text severity label (emoji-free) per severity.
     *
     * @var array<string, string>
     */
    protected const SEVERITY_LABELS = [
        'critical' => '[CRITICAL]',
        'high'     => '[HIGH]',
        'medium'   => '[MEDIUM]',
        'low'      => '[LOW]',
    ];

    /**
     * Build the Telegram markdown message for an alert.
     */
    public static function message(SecurityAlert $alert): string
    {
        $isTest = !empty($alert->metadata['_is_test'] ?? null);

        $title = $isTest
            ? 'Channel Connectivity Test'
            : 'Security Threat Detected';

        $label = self::severityLabel($alert->severity);

        $lines = [
            sprintf('%s *%s*', $label, $title),
            '',
            sprintf('• *Threat Type:* `%s`', self::sanitizeCodeField((string) $alert->threat_type)),
            sprintf('• *Rule:* `%s`', self::sanitizeCodeField((string) ($alert->rule_identifier ?: 'unknown'))),
        ];

        if (filled($alert->fingerprint)) {
            $lines[] = sprintf('• *Fingerprint:* `%s`', substr($alert->fingerprint, 0, 16) . '...');
        }

        $lines[] = sprintf('• *Timestamp:* `%s`', $alert->created_at?->toIso8601String() ?: gmdate('c'));

        $metadata = $alert->metadata ?? [];
        unset($metadata['_is_test'], $metadata['source']);

        if (!empty($metadata)) {
            $lines[] = '';
            $lines[] = '• *Metadata Summary:*';
            $json = (string) json_encode($metadata, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
            // Defang triple backticks to prevent Telegram markdown parsing crash
            $json = str_replace('```', "'''", $json);
            if (strlen($json) > 2500) {
                $json = substr($json, 0, 2400) . "\n... [TRUNCATED FOR TELEGRAM LIMIT]";
            }
            $lines[] = sprintf("```json\n%s\n```", $json);
        }

        $result = implode("\n", $lines);

        // Telegram maximum message limit is 4096 characters
        if (strlen($result) > 4000) {
            $result = substr($result, 0, 3950) . "\n... [TRUNCATED]";
        }

        return $result;
    }

    /**
     * Resolve the text severity label, falling back to [LOW].
     */
    protected static function severityLabel(string $severity): string
    {
        return self::SEVERITY_LABELS[strtolower($severity)] ?? self::SEVERITY_LABELS['low'];
    }

    /**
     * Escape Telegram Markdown control characters in dynamic values.
     */
    protected static function sanitizeCodeField(string $value): string
    {
        // Inside a Telegram code span, backticks are the only control that can
        // close the span; newlines are also structural. Defang both, keep the
        // rest literal so underscores/asterisks display as written.
        return str_replace(["`", "\r\n", "\n"], ["'", ' ', ' '], $value);
    }
}
