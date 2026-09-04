<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Support;

/**
 * Sanitizer for redacting sensitive credentials and tokens from telemetry and alerts.
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
     * @return array<string, mixed>
     */
    public static function clean(array $data, ?array $customSensitiveKeys = null): array
    {
        $keysToRedact = $customSensitiveKeys ?? static::$sensitiveKeys;
        $sanitized = [];

        foreach ($data as $key => $value) {
            if (static::isSensitiveKey((string) $key, $keysToRedact)) {
                $sanitized[$key] = '[REDACTED]';
                continue;
            }

            if (is_array($value)) {
                $sanitized[$key] = static::clean($value, $keysToRedact);
            } elseif (is_string($value)) {
                $sanitized[$key] = static::cleanString($value);
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
     * Scrub sensitive patterns that might appear within string values (e.g., Bearer tokens).
     */
    public static function cleanString(string $value): string
    {
        // Redact Bearer tokens in headers/strings
        $value = (string) preg_replace('/Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*/i', 'Bearer [REDACTED]', $value);

        // Redact basic auth in URLs
        $value = (string) preg_replace('/:\/\/[^:]+:[^@]+@/', '://[REDACTED]:[REDACTED]@', $value);

        return $value;
    }
}
