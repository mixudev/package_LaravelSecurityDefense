<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Services;

use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Cache;
use Mixudev\SecurityDefense\Models\SecurityAlert;
use Mixudev\SecurityDefense\Models\SecurityQuarantine;
use Throwable;

/**
 * Enterprise Dashboard Analytics Engine.
 * Provides high-speed, cached telemetry aggregation and health indices.
 */
class DashboardAnalyticsService
{
    protected string $cachePrefix;
    protected int $cacheTtl;

    public function __construct()
    {
        $this->cachePrefix = (string) config('security-defense.cache_prefix', 'security_defense:');
        $this->cacheTtl = 30; // 30s TTL for high-throughput resilience
    }

    /**
     * Clear all cached dashboard analytics keys.
     */
    public function clearCache(): void
    {
        Cache::forget($this->cachePrefix . 'dash_stats');
        Cache::forget($this->cachePrefix . 'dash_hourly');
        Cache::forget($this->cachePrefix . 'dash_threat_dist');
        Cache::forget($this->cachePrefix . 'dash_quarantines');
        Cache::forget($this->cachePrefix . 'dash_channels');
    }

    /**
     * Retrieve aggregated KPI metrics with micro-caching.
     *
     * @return array<string, int>
     */
    public function getStats(bool $refresh = false): array
    {
        if ($refresh) {
            Cache::forget($this->cachePrefix . 'dash_stats');
        }

        return Cache::remember($this->cachePrefix . 'dash_stats', $this->cacheTtl, function () {
            return [
                'total' => SecurityAlert::query()->count(),
                'new' => SecurityAlert::query()->new()->count(),
                'acknowledged' => SecurityAlert::query()->acknowledged()->count(),
                'resolved' => SecurityAlert::query()->resolved()->count(),
                'critical' => SecurityAlert::query()->severity('critical')->count(),
                'high' => SecurityAlert::query()->severity('high')->count(),
                'medium' => SecurityAlert::query()->severity('medium')->count(),
                'low' => SecurityAlert::query()->severity('low')->count(),
            ];
        });
    }

    /**
     * Retrieve 24-hour incident timeline velocity data.
     *
     * @return array{labels: array<int, string>, totals: array<int, int>, criticals: array<int, int>, peak: int}
     */
    public function getHourlyTimeline(bool $refresh = false): array
    {
        if ($refresh) {
            Cache::forget($this->cachePrefix . 'dash_hourly');
        }

        return Cache::remember($this->cachePrefix . 'dash_hourly', $this->cacheTtl, function () {
            $start = now()->subHours(23)->startOfHour();
            $alerts = SecurityAlert::query()
                ->where('created_at', '>=', $start)
                ->select(['created_at', 'severity'])
                ->get();

            $buckets = [];
            for ($i = 23; $i >= 0; $i--) {
                $hourKey = now()->subHours($i)->format('H:00');
                $buckets[$hourKey] = ['total' => 0, 'critical' => 0];
            }

            foreach ($alerts as $item) {
                if ($item->created_at !== null) {
                    $key = $item->created_at->format('H:00');
                    if (isset($buckets[$key])) {
                        $buckets[$key]['total']++;
                        if ($item->severity === 'critical' || $item->severity === 'high') {
                            $buckets[$key]['critical']++;
                        }
                    }
                }
            }

            return [
                'labels' => array_keys($buckets),
                'totals' => array_column($buckets, 'total'),
                'criticals' => array_column($buckets, 'critical'),
                'peak' => max(array_merge([0], array_column($buckets, 'total'))),
            ];
        });
    }

    /**
     * Retrieve incident distribution grouped by attack vector.
     *
     * @return array<string, int>
     */
    public function getThreatDistribution(bool $refresh = false): array
    {
        if ($refresh) {
            Cache::forget($this->cachePrefix . 'dash_threat_dist');
        }

        return Cache::remember($this->cachePrefix . 'dash_threat_dist', $this->cacheTtl, function () {
            return SecurityAlert::query()
                ->selectRaw('threat_type, count(*) as count')
                ->groupBy('threat_type')
                ->orderByDesc('count')
                ->limit(8)
                ->pluck('count', 'threat_type')
                ->all();
        });
    }

    /**
     * Retrieve active IP quarantines currently jailed.
     */
    public function getActiveQuarantines(bool $refresh = false): Collection
    {
        if ($refresh) {
            Cache::forget($this->cachePrefix . 'dash_quarantines');
        }

        return Cache::remember($this->cachePrefix . 'dash_quarantines', 15, function () {
            try {
                if (class_exists(SecurityQuarantine::class)) {
                    return SecurityQuarantine::query()->active()->latest()->limit(20)->get();
                }
            } catch (Throwable) {
            }
            return collect([]);
        });
    }

    /**
     * Calculate continuous security defense posture score (0 - 100%).
     *
     * @param array<string, int> $stats
     */
    public function calculatePostureScore(array $stats): int
    {
        $unresolvedCritical = (int) ($stats['critical'] ?? 0);
        if ($unresolvedCritical > 0) {
            return max(35, 100 - ($unresolvedCritical * 12));
        }

        return 100;
    }

    /**
     * Retrieve paginated security alerts based on active filters.
     *
     * @param array<string, mixed> $filters
     */
    public function getFilteredAlerts(array $filters, int $perPage = 15): LengthAwarePaginator
    {
        $query = SecurityAlert::query()->latest();

        if (!empty($filters['status'])) {
            $query->where('status', (string) $filters['status']);
        }

        if (!empty($filters['severity'])) {
            $query->where('severity', (string) $filters['severity']);
        }

        if (!empty($filters['threat_type'])) {
            $query->where('threat_type', (string) $filters['threat_type']);
        }

        return $query->paginate($perPage)->withQueryString();
    }
}
