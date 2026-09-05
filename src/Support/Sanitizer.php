<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Support;

use Illuminate\Support\Facades\Config;
use Throwable;

/**
 * Sanitizer for redacting sensitive credentials and tokens from telemetry and alerts.
 * Hardened against memory exhaustion, deep recursive payloads, and standalone environments.
 */
class Sanitizer
{
    /**
     * Default list of sensitive key patterns (case-insensitive substring/regex matches).
     *
     * @var array<string>
     */
    protected static array $sensitiveKeys = [
        'password',
        'password_confirmation',
        'passphrase',
        'secret',
        'token',
        'access_token',
        'refresh_token',
        'api_key',
        'apikey',
        'authorization',
        'bearer',
        'cookie',
        'cvv',
        'cvc',
        'credit_card',
        'card_number',
        'pin',
        'otp',
        'totp',
        'bot_token',
        'webhook_url',
        'private_key',
    ];

    /**
     * Redact sensitive keys from an associative array recursively.
     *
     * @param array<string, mixed> $data
     * @param array<string>|null $customSensitiveKeys
     * @param int $depth Current recursion depth
     * @return array<string, mixed>
     */
    public static function clean(array $data, ?array $customSensitiveKeys = null, int $depth = 0): array
    {
        $maxDepth = static::resolveConfigInt('security-defense.hardening.max_traversal_depth', 5);
        if ($depth >= $maxDepth) {
            return ['_truncated_depth' => 'Depth limit reached'];
        }

        $keysToRedact = $customSensitiveKeys ?? static::$sensitiveKeys;
        $maxInspectionLength = static::resolveConfigInt('security-defense.hardening.max_inspection_length', 4096);
        $sanitized = [];

        foreach ($data as $key => $value) {
            if (static::isSensitiveKey((string) $key, $keysToRedact)) {
                $sanitized[$key] = '[REDACTED]';
                continue;
            }

            if (is_array($value)) {
                $sanitized[$key] = static::clean($value, $keysToRedact, $depth + 1);
            } elseif (is_string($value)) {
                $sanitizedString = static::cleanString($value);
                if (strlen($sanitizedString) > $maxInspectionLength) {
                    $sanitized[$key] = substr($sanitizedString, 0, $maxInspectionLength) . '...[TRUNCATED]';
                } else {
                    $sanitized[$key] = $sanitizedString;
                }
            } else {
                $sanitized[$key] = $value;
            }
        }

        return $sanitized;
    }

    /**
     * Check whether a given key name matches sensitive patterns.
     *
     * @param string $key
     * @param array<string> $keysToRedact
     * @return bool
     */
    public static function isSensitiveKey(string $key, array $keysToRedact): bool
    {
        $normalizedKey = strtolower(trim($key));

        foreach ($keysToRedact as $sensitivePattern) {
            $normalizedPattern = strtolower(trim($sensitivePattern));
            if ($normalizedKey === $normalizedPattern || str_contains($normalizedKey, $normalizedPattern)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Scrub sensitive patterns that might appear within string values (e.g., Bearer tokens)
     * and defang active executable payloads (XSS, shell injection, markdown breakouts).
     */
    public static function cleanString(string $value): string
    {
        // 1. Redact Bearer tokens in headers/strings
        $value = (string) preg_replace('/Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*/i', 'Bearer [REDACTED]', $value);

        // 2. Redact basic auth in URLs
        $value = (string) preg_replace('/:\/\/[^:]+:[^@]+@/', '://[REDACTED]:[REDACTED]@', $value);

        // 3. Defang dangerous executable payloads (XSS, script injection, control characters)
        return static::defangString($value);
    }

    /**
     * Neutralize and defang active payloads so they cannot execute if rendered or transmitted,
     * while preserving the exact semantic structure so security analysts and auditors can inspect it.
     */
    public static function defangString(string $value): string
    {
        // Strip ASCII null bytes and non-printable control characters (anti-CRLF & anti-log poisoning)
        $value = (string) preg_replace('/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/', '', $value);

        // Defang dangerous HTML tags (<script ...> -> [script ...], </script> -> [/script])
        $tagsRegex = 'script|iframe|object|embed|applet|svg|meta|link|style|base';
        $value = (string) preg_replace("/<(\/?)\s*({$tagsRegex})([^>]*)>/i", '[$1$2$3]', $value);
        // Also catch unclosed opening tags (<script ...)
        $value = (string) preg_replace("/<(\/?)\s*({$tagsRegex})\b/i", '[$1$2', $value);

        // Defang any remaining closing tags
        $value = (string) preg_replace('/<\s*\/\s*([a-zA-Z0-9]+)\s*>/', '[/$1]', $value);

        // Defang DOM event handlers (onerror= -> on_error=, onload= -> on_load=)
        $value = (string) preg_replace('/\b(on(?:error|load|click|mouseover|focus|blur|change|submit|input))\s*=/i', '$1_neutralized=', $value);

        // Defang dangerous pseudo-schemes (javascript: -> java_script:, data:text/html -> d_ata:text/html)
        $value = (string) preg_replace('/javascript\s*:/i', 'java_script:', $value);
        $value = (string) preg_replace('/vbscript\s*:/i', 'vb_script:', $value);
        $value = (string) preg_replace('/data\s*:\s*text\/html/i', 'd_ata:text/html', $value);

        // Defang triple backticks to prevent Telegram/Discord markdown code block breakouts
        $value = str_replace('```', "'''", $value);

        return $value;
    }

    /**
     * Safely resolve integer config with fallback for standalone/unbooted environments.
     */
    protected static function resolveConfigInt(string $key, int $default): int
    {
        try {
            if (class_exists(Config::class) && Config::hasFacadeRoot()) {
                return (int) Config::get($key, $default);
            }
        } catch (Throwable) {
            // Fallback if container is not initialized
        }

        return $default;
    }
}
