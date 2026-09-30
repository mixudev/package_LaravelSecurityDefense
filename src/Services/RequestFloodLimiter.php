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

        // Seed the TTL FIRST. increment() on a missing key calls forever() with
        // no expiry, so incrementing before add() makes the following add() a
        // permanent no-op and the window never expires. Because the flood key
        // is time-bucketed, that leaked one key per window per IP forever.
        $cache->add($key, 0, $window);
        $count = (int) $cache->increment($key);

        if ($count <= $max) {
            return false;
        }

        // Exceeded: count consecutive windows; jail once past threshold.
        // Same ordering rule — seed the TTL before incrementing, otherwise the
        // strike counter accumulates for the life of the cache and re-jails the
        // IP on every later flood with no way to shed strikes.
        $strikeKey = sprintf('%sflood:strike:%s', $prefix, md5($ip));
        $cache->add($strikeKey, 0, $window * 4);
        $strikes = (int) $cache->increment($strikeKey);

        if ($strikes >= $targetJail) {
            $this->quarantineService->jail($ip, null, 'Auto-quarantined: request flood exceeding ' . $max . ' req/s per IP');
        }

        // Always reject while over cap (fail-closed under active flood)
        return true;
    }
}