<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Support\Traits;

use Illuminate\Database\Eloquent\Model;
use Mixudev\SecurityDefense\Services\DataAuditService;

/**
 * Trait to automatically capture audit trail and detect parameter tampering on Eloquent models.
 */
trait HasSecurityAudit
{
    /**
     * Boot the trait for the model.
     */
    public static function bootHasSecurityAudit(): void
    {
        if (! config('security-defense.data_audit.enabled', true)) {
            return;
        }

        static::created(function (Model $model) {
            app(DataAuditService::class)->recordMutation($model, 'created');
        });

        static::updated(function (Model $model) {
            app(DataAuditService::class)->recordMutation($model, 'updated');
        });

        static::deleted(function (Model $model) {
            app(DataAuditService::class)->recordMutation($model, 'deleted');
        });

        if (method_exists(static::class, 'restored')) {
            static::restored(function (Model $model) {
                app(DataAuditService::class)->recordMutation($model, 'restored');
            });
        }
    }

    /**
     * Columns that should be excluded from audit logging.
     *
     * @return array<string>
     */
    public function getSecurityAuditExcludedColumns(): array
    {
        /** @phpstan-ignore-next-line */
        return property_exists($this, 'securityAuditExclude') && is_array($this->securityAuditExclude)
            ? $this->securityAuditExclude
            : (array) config('security-defense.data_audit.default_excluded_fields', ['updated_at', 'created_at']);
    }

    /**
     * Columns whose values must be redacted to prevent sensitive data leakage.
     *
     * @return array<string>
     */
    public function getSecurityAuditMaskedColumns(): array
    {
        /** @phpstan-ignore-next-line */
        return property_exists($this, 'securityAuditMasked') && is_array($this->securityAuditMasked)
            ? $this->securityAuditMasked
            : (array) config('security-defense.data_audit.default_masked_fields', [
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
