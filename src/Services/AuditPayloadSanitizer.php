<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Services;

use DateTimeInterface;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Mixudev\SecurityDefense\Support\Sanitizer;

/**
 * Sanitization helpers for data-audit payloads: sensitive-key masking,
 * XSS defanging, size bounding, and per-model column resolution.
 */
class AuditPayloadSanitizer
{
    /**
     * Resolve and sanitize payload snapshot with bounded length.
     *
     * @param Request|null $request
     * @return array<string, mixed>|null
     */
    public function resolvePayloadSnapshot(?Request $request): ?array
    {
        if ($request === null) {
            return null;
        }

        $all = $request->all();
        if (empty($all)) {
            return null;
        }

        // Clean sensitive data recursively
        $sanitized = Sanitizer::clean($all);

        // Anti-DoS check: limit byte size of JSON
        $encoded = json_encode($sanitized);
        $maxBytes = (int) config('security-defense.data_audit.max_payload_snapshot_bytes', 8192);

        if ($encoded !== false && strlen($encoded) > $maxBytes) {
            return [
                '_snapshot_warning' => "Payload exceeded maximum allowed size ({$maxBytes} bytes). Truncated for security.",
                'preview' => array_slice($sanitized, 0, 10, true),
            ];
        }

        return $sanitized;
    }

    /**
     * Mask sensitive columns from an array of values.
     *
     * @param array<string, mixed> $values
     * @param array<string> $maskedColumns
     * @return array<string, mixed>
     */
    public function maskValues(array $values, array $maskedColumns): array
    {
        foreach ($values as $key => $val) {
            if (in_array($key, $maskedColumns, true) || Sanitizer::isSensitiveKey((string) $key, $maskedColumns)) {
                $values[$key] = '******** [REDACTED]';
            } elseif (is_string($val)) {
                // Defang strings in old/new values so stored XSS or executable scripts NEVER reside in audit table
                $values[$key] = Sanitizer::cleanString($val);
            } elseif (is_array($val)) {
                $values[$key] = Sanitizer::clean($val, $maskedColumns);
            }
        }

        return $values;
    }

    /**
     * Normalize attribute value for JSON serialization.
     */
    public function normalizeValue(mixed $value): mixed
    {
        if ($value instanceof DateTimeInterface) {
            return $value->format('Y-m-d H:i:s');
        }

        if (is_object($value) && method_exists($value, '__toString')) {
            return (string) $value;
        }

        return $value;
    }

    /**
     * Resolve excluded columns for a model.
     *
     * @return array<string>
     */
    public function resolveExcludedColumns(Model $model): array
    {
        if (method_exists($model, 'getSecurityAuditExcludedColumns')) {
            return $model->getSecurityAuditExcludedColumns();
        }

        return (array) config('security-defense.data_audit.default_excluded_fields', ['updated_at', 'created_at']);
    }

    /**
     * Resolve masked columns for a model.
     *
     * @return array<string>
     */
    public function resolveMaskedColumns(Model $model): array
    {
        if (method_exists($model, 'getSecurityAuditMaskedColumns')) {
            return $model->getSecurityAuditMaskedColumns();
        }

        return (array) config('security-defense.data_audit.default_masked_fields', [
            'password',
            'password_hash',
            'remember_token',
            'api_token',
            'secret',
            'two_factor_secret',
            'credit_card',
            'cvv',
        ]);
    }
}