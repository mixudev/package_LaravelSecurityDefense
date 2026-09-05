<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphTo;

/**
 * Eloquent model representing database mutation and audit record.
 *
 * @property int $id
 * @property string $event
 * @property string $auditable_type
 * @property string $auditable_id
 * @property string|null $actor_id
 * @property string|null $actor_type
 * @property string $ip_address
 * @property string|null $user_agent
 * @property string|null $request_url
 * @property string $request_method
 * @property string|null $request_route
 * @property array<string, mixed>|null $old_values
 * @property array<string, mixed>|null $new_values
 * @property array<string>|null $modified_fields
 * @property array<string, mixed>|null $payload_snapshot
 * @property bool $is_tampered
 * @property array<string>|null $tamper_reasons
 * @property \Illuminate\Support\Carbon $created_at
 * @property \Illuminate\Support\Carbon $updated_at
 *
 * @method static Builder|SecurityDataAudit tampered()
 * @method static Builder|SecurityDataAudit forAuditable(string $type, ?string $id = null)
 * @method static Builder|SecurityDataAudit forActor(string $id, ?string $type = null)
 */
class SecurityDataAudit extends Model
{
    public const EVENT_CREATED = 'created';
    public const EVENT_UPDATED = 'updated';
    public const EVENT_DELETED = 'deleted';
    public const EVENT_RESTORED = 'restored';

    protected $guarded = ['id'];

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'old_values' => 'array',
            'new_values' => 'array',
            'modified_fields' => 'array',
            'payload_snapshot' => 'array',
            'is_tampered' => 'boolean',
            'tamper_reasons' => 'array',
        ];
    }

    /**
     * Dynamically resolve table name from package configuration.
     */
    public function getTable(): string
    {
        return config('security-defense.data_audit.table', parent::getTable() ?: 'security_data_audits');
    }

    /**
     * Polymorphic relation to the auditable model.
     *
     * @return MorphTo<Model, SecurityDataAudit>
     */
    public function auditable(): MorphTo
    {
        return $this->morphTo();
    }

    /**
     * Polymorphic relation to the actor (User/Admin/etc.)
     *
     * @return MorphTo<Model, SecurityDataAudit>
     */
    public function actor(): MorphTo
    {
        return $this->morphTo();
    }

    /**
     * Scope for records where Burp Suite / Parameter Tampering was detected.
     *
     * @param Builder<SecurityDataAudit> $query
     * @return Builder<SecurityDataAudit>
     */
    public function scopeTampered(Builder $query): Builder
    {
        return $query->where('is_tampered', true);
    }

    /**
     * Scope for a specific auditable model.
     *
     * @param Builder<SecurityDataAudit> $query
     * @param string $type
     * @param string|null $id
     * @return Builder<SecurityDataAudit>
     */
    public function scopeForAuditable(Builder $query, string $type, ?string $id = null): Builder
    {
        $query->where('auditable_type', $type);

        if ($id !== null) {
            $query->where('auditable_id', $id);
        }

        return $query;
    }

    /**
     * Scope for a specific actor.
     *
     * @param Builder<SecurityDataAudit> $query
     * @param string $id
     * @param string|null $type
     * @return Builder<SecurityDataAudit>
     */
    public function scopeForActor(Builder $query, string $id, ?string $type = null): Builder
    {
        $query->where('actor_id', $id);

        if ($type !== null) {
            $query->where('actor_type', $type);
        }

        return $query;
    }

    /**
     * Get HTML-escaped safe payload representation for dashboard or UI rendering.
     *
     * @return array<string, mixed>|null
     */
    public function getSafePayloadAttribute(): ?array
    {
        if ($this->payload_snapshot === null) {
            return null;
        }

        return $this->recursivelySanitizeForDisplay($this->payload_snapshot);
    }

    /**
     * Recursively escape string values against HTML/script injection.
     *
     * @param mixed $data
     * @return mixed
     */
    protected function recursivelySanitizeForDisplay(mixed $data): mixed
    {
        if (is_array($data)) {
            $sanitized = [];
            foreach ($data as $key => $val) {
                $sanitized[htmlspecialchars((string) $key, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')] = $this->recursivelySanitizeForDisplay($val);
            }
            return $sanitized;
        }

        if (is_string($data)) {
            return htmlspecialchars($data, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        }

        return $data;
    }
}
