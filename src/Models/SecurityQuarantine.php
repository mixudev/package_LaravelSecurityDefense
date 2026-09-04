<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;

/**
 * Durable, database-backed IP quarantine record.
 *
 * @property int $id
 * @property string $ip
 * @property \Illuminate\Support\Carbon|null $jailed_at
 * @property \Illuminate\Support\Carbon $expires_at
 * @property string|null $reason
 * @property \Illuminate\Support\Carbon $created_at
 * @property \Illuminate\Support\Carbon $updated_at
 *
 * @method static Builder|SecurityQuarantine active()
 * @method static Builder|SecurityQuarantine forIp(string $ip)
 */
class SecurityQuarantine extends Model
{
    protected $guarded = ['id'];

    protected $casts = [
        'jailed_at' => 'datetime',
        'expires_at' => 'datetime',
    ];

    /**
     * Dynamically resolve table name from package configuration.
     */
    public function getTable(): string
    {
        return config('security-defense.middleware.quarantine.table', parent::getTable() ?: 'security_quarantines');
    }

    /**
     * Scope to active (non-expired) quarantine records.
     *
     * @param Builder<SecurityQuarantine> $query
     * @return Builder<SecurityQuarantine>
     */
    public function scopeActive(Builder $query): Builder
    {
        return $query->where('expires_at', '>', now());
    }

    /**
     * Scope to a specific IP.
     *
     * @param Builder<SecurityQuarantine> $query
     * @param string $ip
     * @return Builder<SecurityQuarantine>
     */
    public function scopeForIp(Builder $query, string $ip): Builder
    {
        return $query->where('ip', $ip);
    }
}
