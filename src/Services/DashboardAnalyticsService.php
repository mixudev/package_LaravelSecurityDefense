<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Services;

use Closure;
use Illuminate\Contracts\Pagination\LengthAwarePaginator;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Cache;
use Mixudev\SecurityDefense\Models\SecurityAlert;
use Mixudev\SecurityDefense\Models\SecurityQuarantine;
use Mixudev\SecurityDefense\Support\DateRangeFilter;
use Throwable;

/**
 * Enterprise Dashboard Analytics Engine.
 * Provides high-speed, cached telemetry aggregation and health indices.
 */
class DashboardAnalyticsService
{
    protected string $cachePrefix;
    protected int $defaultTtl;

    public function __construct()
    {
        $this->cachePrefix = (string) config('security-defense.cache_prefix', 'security_defense:');
        $this->defaultTtl = (int) config('security-defense.dashboard.cache.ttl', 30);
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
     * Safely read or compute cache without risk of __PHP_Incomplete_Class.
     */
    protected function rememberSafe(string $key, int $ttl, Closure $callback): mixed
    {
        if (!(bool) config('security-defense.dashboard.cache.enabled', true)) {
            return $callback();
        }

        try {
            $cached = Cache::get($key);
            if ($cached !== null && !($cached instanceof \__PHP_Incomplete_Class)) {
                return $cached;
            }
            if ($cached instanceof \__PHP_Incomplete_Class) {
                Cache::forget($key);
            }
        } catch (Throwable) {
            Cache::forget($key);
        }

        $fresh = $callback();
        try {
            Cache::put($key, $fresh, $ttl);
        } catch (Throwable) {
        }

        return $fresh;
    }

    /**
     * Retrieve aggregated KPI metrics with micro-caching.
     *
     * @return array<string, int>
     */
    public function getStats(bool $refresh = false): array
    {
        $key = $this->cachePrefix . 'dash_stats';
        if ($refresh) {
            Cache::forget($key);
        }

        return $this->rememberSafe($key, $this->defaultTtl, function () {
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
        $key = $this->cachePrefix . 'dash_hourly';
        if ($refresh) {
            Cache::forget($key);
        }

        return $this->rememberSafe($key, $this->defaultTtl, function () {
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
                    $itemHour = $item->created_at->format('H:00');
                    if (isset($buckets[$itemHour])) {
                        $buckets[$itemHour]['total']++;
                        if ($item->severity === 'critical' || $item->severity === 'high') {
                            $buckets[$itemHour]['critical']++;
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
        $key = $this->cachePrefix . 'dash_threat_dist';
        if ($refresh) {
            Cache::forget($key);
        }

        return $this->rememberSafe($key, $this->defaultTtl, function () {
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
     * Guaranteed safe from __PHP_Incomplete_Class deserialization.
     */
    public function getActiveQuarantines(bool $refresh = false): Collection
    {
        try {
            if (class_exists(SecurityQuarantine::class)) {
                return SecurityQuarantine::query()->active()->latest()->limit(20)->get();
            }
        } catch (Throwable) {
        }

        return collect([]);
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

        if (!empty($filters['from']) || !empty($filters['to'])) {
            DateRangeFilter::apply($query, [
                'from' => $filters['from'] ?? null,
                'to' => $filters['to'] ?? null,
            ]);
        }

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

    /**
     * Retrieve the most recent blocked-request events for the live WAF meter.
     *
     * @return array<int, array{id: int, severity: string, threat_type: string, ip: string, url: string, method: string, user_agent: string, created_at: string}>
     */
    public function getLiveBlockedEvents(int $limit = 10): array
    {
        try {
            return SecurityAlert::query()
                ->latest()
                ->limit($limit)
                ->get()
                ->map(function (SecurityAlert $alert): array {
                    $metadata = is_array($alert->metadata) ? $alert->metadata : [];

                    return [
                        'id' => (int) $alert->id,
                        'severity' => (string) $alert->severity,
                        'threat_type' => (string) $alert->threat_type,
                        'ip' => (string) ($metadata['ip'] ?? $metadata['source_ip'] ?? 'N/A'),
                        'url' => (string) ($metadata['url'] ?? $metadata['request_url'] ?? 'N/A'),
                        'method' => (string) ($metadata['method'] ?? $metadata['request_method'] ?? 'GET'),
                        'user_agent' => (string) ($metadata['user_agent'] ?? 'N/A'),
                        'created_at' => $alert->created_at->toIso8601String(),
                    ];
                })
                ->all();
        } catch (Throwable) {
            return [];
        }
    }
}
