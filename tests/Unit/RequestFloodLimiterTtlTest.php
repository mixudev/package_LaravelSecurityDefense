<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Unit;

use Illuminate\Support\Facades\Cache;
use Mixudev\SecurityDefense\Services\RequestFloodLimiter;
use Mixudev\SecurityDefense\Tests\TestCase;

/**
 * Regression: the flood limiter seeded its TTL AFTER increment().
 *
 * Illuminate's increment() on a missing key calls forever() — no TTL — so the
 * following add() is a permanent no-op and the counter window never expires.
 * Two consequences in production:
 *   1. Cache leak: the flood key is time-bucketed, so a new key is minted every
 *      `window` seconds per IP and none of them ever expire.
 *   2. The strike counter has no time-bucket, so once an IP reaches the strike
 *      threshold it is re-jailed on every later flood, forever.
 */
final class RequestFloodLimiterTtlTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        config()->set('security-defense.enabled', true);
        config()->set('security-defense.cache_store', 'array');
        config()->set('security-defense.middleware.request_flood', [
            'enabled'                 => true,
            'max_requests_per_second' => 3,
            'window'                  => 5,
            'jail_after_exceeding'    => 2,
        ]);

        Cache::forgetDriver();
    }

    private function limiter(): RequestFloodLimiter
    {
        return app(RequestFloodLimiter::class);
    }

    private function floodKey(string $ip, int $window): string
    {
        return sprintf(
            '%sflood:%s:%d',
            (string) config('security-defense.cache_prefix', 'security_defense:'),
            md5($ip),
            (int) floor(time() / $window)
        );
    }

    private function strikeKey(string $ip): string
    {
        return sprintf(
            '%sflood:strike:%s',
            (string) config('security-defense.cache_prefix', 'security_defense:'),
            md5($ip)
        );
    }

    public function test_flood_counter_expires_within_the_configured_window(): void
    {
        $ip = '198.51.100.31';
        $limiter = $this->limiter();

        $limiter->isExceeded($ip);

        /** @var \Illuminate\Contracts\Cache\Repository $repo */
        $repo = Cache::store('array');

        $key = $this->floodKey($ip, 5);

        // The counter must carry an expiry so the key cannot outlive its window.
        self::assertTrue(
            $this->storeHasExpiry($repo, $key),
            'Flood counter was stored without a TTL; it can never expire.'
        );
    }

    public function test_strike_counter_expires_so_strikes_reset(): void
    {
        $ip = '198.51.100.32';
        $limiter = $this->limiter();

        // Trip the cap to earn strikes.
        for ($i = 0; $i < 6; $i++) {
            $limiter->isExceeded($ip);
        }

        /** @var \Illuminate\Contracts\Cache\Repository $repo */
        $repo = Cache::store('array');
        $strike = $this->strikeKey($ip);

        self::assertTrue(
            $this->storeHasExpiry($repo, $strike),
            'Strike counter was stored without a TTL; strikes accumulate forever '
            . 'and the IP is re-jailed on every later flood.'
        );
    }

    public function test_limiter_still_counts_and_blocks_at_the_cap(): void
    {
        $ip = '198.51.100.33';
        $limiter = $this->limiter();

        $results = [];
        for ($i = 0; $i < 5; $i++) {
            $results[] = $limiter->isExceeded($ip);
        }

        // cap = 3, so calls 1-3 pass and 4-5 are rejected.
        self::assertSame([false, false, false, true, true], $results);
    }

    /**
     * Does the underlying store hold a non-null expiry for this key?
     */
    private function storeHasExpiry(\Illuminate\Contracts\Cache\Repository $repo, string $key): bool
    {
        $store = $repo->getStore();

        if (! $store instanceof \Illuminate\Cache\ArrayStore) {
            self::markTestSkipped('Expiry introspection requires ArrayStore.');
        }

        $prop = new \ReflectionProperty(\Illuminate\Cache\ArrayStore::class, 'storage');
        $prop->setAccessible(true);
        $storage = $prop->getValue($store);

        if (! isset($storage[$key])) {
            return false;
        }

        $expiresAt = $storage[$key]['expiresAt'] ?? null;

        return $expiresAt !== null && $expiresAt > 0;
    }
}
