<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Models;

use DateTimeInterface;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Mixudev\SecurityDefense\Support\Sanitizer;

/**
 * Eloquent model representing persisted security alert.
 *
 * @property int $id
 * @property string $severity
 * @property string $threat_type
 * @property string $fingerprint
 * @property string $status
 * @property string|null $rule_identifier
 * @property array<string, mixed>|null $metadata
 * @property \Illuminate\Support\Carbon|null $resolved_at
 * @property \Illuminate\Support\Carbon $created_at
 * @property \Illuminate\Support\Carbon $updated_at
 *
 * @method static Builder|SecurityAlert new()
 * @method static Builder|SecurityAlert acknowledged()
 * @method static Builder|SecurityAlert resolved()
 * @method static Builder|SecurityAlert severity(string $severity)
 */
class SecurityAlert extends Model
{
    public const STATUS_NEW = 'new';
    public const STATUS_ACKNOWLEDGED = 'acknowledged';
    public const STATUS_RESOLVED = 'resolved';

    public const SEVERITY_LOW = 'low';
    public const SEVERITY_MEDIUM = 'medium';
    public const SEVERITY_HIGH = 'high';
    public const SEVERITY_CRITICAL = 'critical';

    protected $guarded = ['id'];

    protected $casts = [
        'metadata' => 'array',
        'resolved_at' => 'datetime',
    ];

    /**
     * Dynamically resolve table name from package configuration.
     */
    public function getTable(): string
    {
        return config('security-defense.alerts.database.table', parent::getTable() ?: 'security_alerts');
    }

    /**
     * Mutator to ensure all metadata stored is sanitized.
     *
     * @param array<string, mixed>|null $value
     */
    public function setMetadataAttribute(?array $value): void
    {
        $this->attributes['metadata'] = $value !== null ? json_encode(Sanitizer::clean($value)) : null;
    }

    /**
     * Mark the alert as acknowledged.
     */
    public function acknowledge(): self
    {
        $this->update([
            'status' => self::STATUS_ACKNOWLEDGED,
        ]);

        return $this;
    }

    /**
     * Mark the alert as resolved.
     */
    public function resolve(?DateTimeInterface $resolvedAt = null): self
    {
        $this->update([
            'status' => self::STATUS_RESOLVED,
            'resolved_at' => $resolvedAt ?? now(),
        ]);

        return $this;
    }

    /**
     * Scope alerts by 'new' status.
     *
     * @param Builder<SecurityAlert> $query
     * @return Builder<SecurityAlert>
     */
    public function scopeNew(Builder $query): Builder
    {
        return $query->where('status', self::STATUS_NEW);
    }

    /**
     * Scope alerts by 'acknowledged' status.
     *
     * @param Builder<SecurityAlert> $query
     * @return Builder<SecurityAlert>
     */
    public function scopeAcknowledged(Builder $query): Builder
    {
        return $query->where('status', self::STATUS_ACKNOWLEDGED);
    }

    /**
     * Scope alerts by 'resolved' status.
     *
     * @param Builder<SecurityAlert> $query
     * @return Builder<SecurityAlert>
     */
    public function scopeResolved(Builder $query): Builder
    {
        return $query->where('status', self::STATUS_RESOLVED);
    }

    /**
     * Scope alerts by severity.
     *
     * @param Builder<SecurityAlert> $query
     * @param string $severity
     * @return Builder<SecurityAlert>
     */
    public function scopeSeverity(Builder $query, string $severity): Builder
    {
        return $query->where('severity', strtolower(trim($severity)));
    }
}
