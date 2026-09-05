<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Services;

use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use Illuminate\Support\Facades\Cache;
use Mixudev\SecurityDefense\Models\SecurityDataAudit;
use Mixudev\SecurityDefense\Support\DateRangeFilter;

/**
 * Service for querying, filtering, and aggregating database mutation audits.
 */
class DataAuditQueryService
{
    protected string $cachePrefix;
    protected int $cacheTtl;

    public function __construct()
    {
        $this->cachePrefix = (string) config('security-defense.cache_prefix', 'security_defense:');
        $this->cacheTtl = 30;
    }

    /**
     * Retrieve paginated database audit records with multi-dimensional filtering.
     *
     * @param array<string, mixed> $filters
     */
    public function getAudits(array $filters, int $perPage = 20): LengthAwarePaginator
    {
        $query = SecurityDataAudit::query()->latest();

        if (!empty($filters['from']) || !empty($filters['to'])) {
            DateRangeFilter::apply($query, [
                'from' => $filters['from'] ?? null,
                'to' => $filters['to'] ?? null,
            ]);
        }

        if (!empty($filters['event'])) {
            $query->where('event', (string) $filters['event']);
        }

        if (!empty($filters['auditable_type'])) {
            $query->where('auditable_type', 'like', '%' . (string) $filters['auditable_type'] . '%');
        }

        if (isset($filters['tampered']) && $filters['tampered'] !== '') {
            $tampered = $filters['tampered'];
            if ($tampered === '1' || $tampered === 'true' || $tampered === true) {
                $query->where('is_tampered', true);
            } elseif ($tampered === '0' || $tampered === 'false' || $tampered === false) {
                $query->where('is_tampered', false);
            }
        }

        if (!empty($filters['search'])) {
            $search = (string) $filters['search'];
            $query->where(function ($q) use ($search) {
                $q->where('auditable_id', 'like', "%{$search}%")
                    ->orWhere('actor_id', 'like', "%{$search}%")
                    ->orWhere('ip_address', 'like', "%{$search}%")
                    ->orWhere('request_url', 'like', "%{$search}%");
            });
        }

        return $query->paginate($perPage)->withQueryString();
    }

    /**
     * Retrieve cached aggregate statistics for database mutations.
     *
     * @return array{total: int, tampered: int, today: int, unique_actors: int}
     */
    public function getStats(bool $refresh = false): array
    {
        if ($refresh) {
            Cache::forget($this->cachePrefix . 'audit_stats');
        }

        return Cache::remember($this->cachePrefix . 'audit_stats', $this->cacheTtl, function () {
            return [
                'total' => SecurityDataAudit::query()->count(),
                'tampered' => SecurityDataAudit::query()->where('is_tampered', true)->count(),
                'today' => SecurityDataAudit::query()->whereDate('created_at', now()->toDateString())->count(),
                'unique_actors' => SecurityDataAudit::query()->whereNotNull('actor_id')->distinct('actor_id')->count('actor_id'),
            ];
        });
    }
}
