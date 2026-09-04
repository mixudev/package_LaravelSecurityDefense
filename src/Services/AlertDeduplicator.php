<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Services;

use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Support\Facades\Cache;
use Mixudev\SecurityDefense\Contracts\AlertDeduplicatorInterface;
use Mixudev\SecurityDefense\DTO\SecurityThreat;

/**
 * Deduplicates security alerts using fingerprint hash within a sliding time window.
 */
class AlertDeduplicator implements AlertDeduplicatorInterface
{
    public function __construct(protected ?CacheRepository $cache = null)
    {
    }

    protected function getCache(): CacheRepository
    {
        if ($this->cache !== null) {
            return $this->cache;
        }

        $store = config('security-defense.cache_store');

        return Cache::store($store);
    }

    protected function getCacheKey(string $fingerprint): string
    {
        $prefix = (string) config('security-defense.cache_prefix', 'security_defense:');

        return sprintf('%sdedupe:%s', $prefix, $fingerprint);
    }

    /**
     * Determine whether an alert should be emitted or suppressed.
     */
    public function shouldAlert(SecurityThreat $threat): bool
    {
        $enabled = (bool) config('security-defense.deduplication.enabled', true);
        if (!$enabled) {
            return true;
        }

        $cacheKey = $this->getCacheKey($threat->fingerprint);

        return !$this->getCache()->has($cacheKey);
    }

    /**
     * Record the threat fingerprint into cache for the configured window.
     */
    public function record(SecurityThreat $threat): void
    {
        $enabled = (bool) config('security-defense.deduplication.enabled', true);
        if (!$enabled) {
            return;
        }

        $window = (int) config('security-defense.deduplication.window', 300);
        $cacheKey = $this->getCacheKey($threat->fingerprint);

        $this->getCache()->put($cacheKey, [
            'threat_type' => $threat->threatType,
            'severity' => $threat->severity,
            'recorded_at' => time(),
        ], $window);
    }

    /**
     * Forget a fingerprint to allow immediate alerting again.
     */
    public function forget(string $fingerprint): void
    {
        $cacheKey = $this->getCacheKey($fingerprint);
        $this->getCache()->forget($cacheKey);
    }
}
