<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Services;

use DateTimeInterface;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Mixudev\SecurityDefense\Models\SecurityDataAudit;
use Mixudev\SecurityDefense\Support\Sanitizer;
use Throwable;

/**
 * Enterprise service for database mutation monitoring, zero-leakage audit trailing,
 * and Burp Suite / parameter tampering detection.
 */
class DataAuditService
{
    public function __construct(
        protected ?Request $request = null,
        protected ?SecurityDefenseManager $defenseManager = null,
    ) {
    }

    /**
     * Record a model mutation lifecycle event.
     */
    public function recordMutation(Model $model, string $event): ?SecurityDataAudit
    {
        if (! config('security-defense.data_audit.enabled', true)) {
            return null;
        }

        try {
            $excluded = $this->resolveExcludedColumns($model);
            $masked = $this->resolveMaskedColumns($model);

            $oldValues = [];
            $newValues = [];
            $modifiedFields = [];

            if ($event === SecurityDataAudit::EVENT_CREATED) {
                $attributes = $model->getAttributes();
                foreach ($attributes as $column => $value) {
                    if (in_array($column, $excluded, true)) {
                        continue;
                    }
                    $newValues[$column] = $this->normalizeValue($value);
                    $modifiedFields[] = $column;
                }
            } elseif ($event === SecurityDataAudit::EVENT_DELETED) {
                $attributes = $model->getOriginal() ?: $model->getAttributes();
                foreach ($attributes as $column => $value) {
                    if (in_array($column, $excluded, true)) {
                        continue;
                    }
                    $oldValues[$column] = $this->normalizeValue($value);
                    $modifiedFields[] = $column;
                }
            } else {
                // Updated or Restored
                $dirty = $model->getDirty();
                $original = $model->getOriginal();

                foreach ($dirty as $column => $newValue) {
                    if (in_array($column, $excluded, true)) {
                        continue;
                    }
                    $oldValues[$column] = $this->normalizeValue($original[$column] ?? null);
                    $newValues[$column] = $this->normalizeValue($newValue);
                    $modifiedFields[] = $column;
                }

                if (empty($modifiedFields) && $event === SecurityDataAudit::EVENT_UPDATED) {
                    return null; // No relevant fields changed
                }
            }

            // Redact sensitive values from old and new values
            $oldValues = $this->maskValues($oldValues, $masked);
            $newValues = $this->maskValues($newValues, $masked);

            // Burp Suite & Parameter Tampering Analysis
            $tamperAnalysis = $this->analyzeTampering($model, $modifiedFields);

            // Request Context Telemetry
            $request = $this->resolveRequest();
            $actor = $this->resolveActor();
            $payloadSnapshot = $this->resolvePayloadSnapshot($request);

            /** @var SecurityDataAudit $audit */
            $audit = SecurityDataAudit::query()->create([
                'event' => $event,
                'auditable_type' => get_class($model),
                'auditable_id' => (string) $model->getKey(),
                'actor_id' => $actor['id'],
                'actor_type' => $actor['type'],
                'ip_address' => $request?->ip() ?? '127.0.0.1',
                'user_agent' => substr((string) ($request?->userAgent() ?? 'CLI / System Process'), 0, 500),
                'request_url' => $request ? substr($request->fullUrl(), 0, 1000) : 'CLI Console Command',
                'request_method' => $request?->method() ?? 'CLI',
                'request_route' => $request?->route()?->getName(),
                'old_values' => empty($oldValues) ? null : $oldValues,
                'new_values' => empty($newValues) ? null : $newValues,
                'modified_fields' => $modifiedFields,
                'payload_snapshot' => $payloadSnapshot,
                'is_tampered' => $tamperAnalysis['is_tampered'],
                'tamper_reasons' => $tamperAnalysis['reasons'],
            ]);

            // If tampering detected and alerts enabled, notify Security SIEM
            if ($tamperAnalysis['is_tampered'] && config('security-defense.data_audit.alert_on_tampering', true)) {
                $this->dispatchTamperAlert($audit, $tamperAnalysis['reasons']);
            }

            return $audit;
        } catch (Throwable $e) {
            // Fail-safe: database mutation audit should never crash host business transactions
            report($e);

            return null;
        }
    }

    /**
     * Analyze if modified attributes indicate Burp Suite manipulation or parameter tampering.
     *
     * @param Model $model
     * @param array<string> $modifiedFields
     * @return array{is_tampered: bool, reasons: array<string>}
     */
    public function analyzeTampering(Model $model, array $modifiedFields): array
    {
        $request = $this->resolveRequest();
        if ($request === null || $request->isMethod('GET') || $request->isMethod('HEAD')) {
            return ['is_tampered' => false, 'reasons' => []];
        }

        $reasons = [];
        $requestData = $request->all();
        $payloadKeys = array_keys($requestData);

        // 1. Sensitive Field Injected Directly via HTTP Payload
        $sensitiveColumns = (array) config('security-defense.data_audit.sensitive_watch_fields', [
            'is_admin',
            'role',
            'role_id',
            'permissions',
            'balance',
            'credit',
            'status',
            'email_verified_at',
        ]);

        foreach ($modifiedFields as $field) {
            if (in_array($field, $sensitiveColumns, true) && in_array($field, $payloadKeys, true)) {
                $reasons[] = "Sensitive column '{$field}' was altered directly from HTTP request payload (potential Burp Suite tampering/mass assignment)";
            }
        }

        // 2. Unguarded / Non-Fillable Field Mutation Injected via Request
        $fillable = $model->getFillable();
        if (! empty($fillable)) {
            foreach ($modifiedFields as $field) {
                if (! in_array($field, $fillable, true) && in_array($field, $payloadKeys, true)) {
                    $reasons[] = "Field '{$field}' is not in fillable whitelist but was passed via request payload and persisted";
                }
            }
        }

        // 3. Canary / Honeypot Traps
        $honeypotKey = (string) config('security-defense.data_audit.honeypot_field', '_system_sync_token');
        if (isset($requestData[$honeypotKey]) && (string) $requestData[$honeypotKey] !== '') {
            $reasons[] = "Automated bot / form-grabber trap triggered: honeypot field '{$honeypotKey}' was filled";
        }

        return [
            'is_tampered' => ! empty($reasons),
            'reasons' => array_values(array_unique($reasons)),
        ];
    }

    /**
     * Dispatch alert to Security Defense SIEM when tampering is identified.
     *
     * @param SecurityDataAudit $audit
     * @param array<string> $reasons
     */
    protected function dispatchTamperAlert(SecurityDataAudit $audit, array $reasons): void
    {
        try {
            $manager = $this->defenseManager ?? (app()->bound(SecurityDefenseManager::class) ? app(SecurityDefenseManager::class) : null);
            if ($manager === null) {
                return;
            }

            $manager->record([
                'ip' => $audit->ip_address,
                'identifier' => $audit->actor_id ?? 'guest',
                'eventType' => 'DatabaseTamperingDetected',
                'userAgent' => $audit->user_agent,
                'metadata' => [
                    'model' => $audit->auditable_type,
                    'model_id' => $audit->auditable_id,
                    'modified_fields' => $audit->modified_fields,
                    'url' => $audit->request_url,
                    'reasons' => $reasons,
                ],
            ]);
        } catch (Throwable) {
            // Fail-safe
        }
    }

    /**
     * Resolve and sanitize payload snapshot with bounded length.
     *
     * @param Request|null $request
     * @return array<string, mixed>|null
     */
    protected function resolvePayloadSnapshot(?Request $request): ?array
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
    protected function maskValues(array $values, array $maskedColumns): array
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
    protected function normalizeValue(mixed $value): mixed
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
    protected function resolveExcludedColumns(Model $model): array
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
    protected function resolveMaskedColumns(Model $model): array
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

    /**
     * Safely resolve the current HTTP request.
     */
    protected function resolveRequest(): ?Request
    {
        if ($this->request !== null) {
            return $this->request;
        }

        try {
            return app()->bound('request') ? app('request') : null;
        } catch (Throwable) {
            return null;
        }
    }

    /**
     * Safely resolve actor ID and Type without coupling to host User model.
     *
     * @return array{id: string|null, type: string|null}
     */
    protected function resolveActor(): array
    {
        try {
            if (class_exists(Auth::class) && Auth::check()) {
                $user = Auth::user();

                return [
                    'id' => $user !== null ? (string) $user->getAuthIdentifier() : null,
                    'type' => $user !== null ? get_class($user) : null,
                ];
            }
        } catch (Throwable) {
            // Container or session not ready
        }

        return ['id' => null, 'type' => null];
    }
}
