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
