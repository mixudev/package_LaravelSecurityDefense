<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Services;

use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use Illuminate\Support\Facades\Cache;
use Mixudev\SecurityDefense\Models\SecurityAlert;

/**
 * Service for querying, filtering, and aggregating session intelligence threats.
 */
class SessionIntelligenceQueryService
{
    public const SESSION_THREAT_TYPES = [
        'session_hijack_suspected',
        'suspicious_velocity_scraping',
        'header_inconsistency_bot',
        'impossible_travel',
    ];

    protected string $cachePrefix;
    protected int $cacheTtl;

    public function __construct()
    {
        $this->cachePrefix = (string) config('security-defense.cache_prefix', 'security_defense:');
        $this->cacheTtl = 30;
    }

    /**
     * Retrieve paginated session threats with filtering.
     *
     * @param array<string, mixed> $filters
     */
    public function getThreats(array $filters, int $perPage = 20): LengthAwarePaginator
    {
        $query = SecurityAlert::query()
            ->whereIn('threat_type', self::SESSION_THREAT_TYPES)
            ->latest();

        if (!empty($filters['threat_type'])) {
            $query->where('threat_type', (string) $filters['threat_type']);
        }

        if (!empty($filters['severity'])) {
            $query->where('severity', (string) $filters['severity']);
        }

        return $query->paginate($perPage)->withQueryString();
    }

    /**
     * Retrieve cached aggregate statistics for session threats.
     *
     * @return array{total_session_threats: int, hijacks_detected: int, velocity_spikes: int, header_anomalies: int}
     */
    public function getStats(bool $refresh = false): array
    {
        if ($refresh) {
            Cache::forget($this->cachePrefix . 'session_stats');
        }

        return Cache::remember($this->cachePrefix . 'session_stats', $this->cacheTtl, function () {
            return [
                'total_session_threats' => SecurityAlert::query()->whereIn('threat_type', self::SESSION_THREAT_TYPES)->count(),
                'hijacks_detected' => SecurityAlert::query()->where('threat_type', 'session_hijack_suspected')->count(),
                'velocity_spikes' => SecurityAlert::query()->where('threat_type', 'suspicious_velocity_scraping')->count(),
                'header_anomalies' => SecurityAlert::query()->where('threat_type', 'header_inconsistency_bot')->count(),
            ];
        });
    }
}
