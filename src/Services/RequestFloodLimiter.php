<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Services;

use Illuminate\Contracts\Cache\Repository;

/**
 * O(1) per-IP request flood limiter using atomic cache counters.
 * Guards against DDoS/scraper floods before expensive regex evaluation.
 */
class RequestFloodLimiter
{
    public function __construct(
        protected IpQuarantineService $quarantineService
    ) {
    }

    /**
     * Cache repository used for flood counters (matches quarantine/scoring store).
     */
    protected function getFloodCache(): Repository
    {
        $store = config('security-defense.cache_store');

        return \Illuminate\Support\Facades\Cache::store($store);
    }

    /**
     * Check if the given IP has exceeded the request flood quota.
     * Always rejects while over cap (fail-closed), and auto-jails once a
     * configured number of consecutive windows have exceeded the cap.
     */
    public function isExceeded(string $ip): bool
    {
        $cfg = (array) config('security-defense.middleware.request_flood', []);
        if (empty($cfg['enabled'])) {
            return false;
        }

        $max = (int) ($cfg['max_requests_per_second'] ?? 200);
        $window = (int) ($cfg['window'] ?? 5);
        $targetJail = (int) ($cfg['jail_after_exceeding'] ?? 2);

        $prefix = (string) config('security-defense.cache_prefix', 'security_defense:');
        $key = sprintf('%sflood:%s:%d', $prefix, md5($ip), (int) floor(time() / $window));

        $cache = $this->getFloodCache();

        // Atomic increment; seeds TTL on first touch
        $count = (int) $cache->increment($key);
        if ($count === 1) {
            $cache->put($key, 1, $window);
        }

        if ($count <= $max) {
            return false;
        }

        // Exceeded: count consecutive windows; jail once past threshold
        $strikeKey = sprintf('%sflood:strike:%s', $prefix, md5($ip));
        $strikes = (int) $cache->increment($strikeKey);
        if ($strikes === 1) {
            $cache->put($strikeKey, 1, $window * 4);
        }
        if ($strikes >= $targetJail) {
            $this->quarantineService->jail($ip, null, 'Auto-quarantined: request flood exceeding ' . $max . ' req/s per IP');
        }

        // Always reject while over cap (fail-closed under active flood)
        return true;
    }
}