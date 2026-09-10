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
     * Atomically claim a fingerprint. This combines check and claim, preventing
     * concurrent requests from both passing a check before either records it.
     */
    public function shouldAlert(SecurityThreat $threat): bool
    {
        if (!(bool) config('security-defense.deduplication.enabled', true)) {
            return true;
        }

        $window = max(1, (int) config('security-defense.deduplication.window', 300));

        return $this->getCache()->add($this->getCacheKey($threat->fingerprint), [
            'threat_type' => $threat->threatType,
            'severity' => $threat->severity,
            'recorded_at' => time(),
        ], $window);
    }

    /**
     * Record a claimed threat. Kept for API compatibility; shouldAlert already
     * performs the atomic cache write, so this must not reset its TTL.
     */
    public function record(SecurityThreat $threat): void
    {
        if (!(bool) config('security-defense.deduplication.enabled', true)) {
            return;
        }

        $window = max(1, (int) config('security-defense.deduplication.window', 300));
        $this->getCache()->add($this->getCacheKey($threat->fingerprint), [
            'threat_type' => $threat->threatType,
            'severity' => $threat->severity,
            'recorded_at' => time(),
        ], $window);
    }

    public function forget(string $fingerprint): void
    {
        $this->getCache()->forget($this->getCacheKey($fingerprint));
    }
}
