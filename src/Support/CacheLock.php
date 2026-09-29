<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Support;

use Illuminate\Contracts\Cache\LockProvider;
use Illuminate\Contracts\Cache\Repository as CacheRepository;

/**
 * Cache lock helper shared by every counter that must not race.
 *
 * The capability check must target the STORE, not the Repository wrapper.
 * Illuminate\Cache\Repository does not declare lock(); it only forwards
 * unknown calls to the store via __call(). So method_exists($cache, 'lock')
 * is FALSE even on Redis/Memcached, and a lock written behind that check
 * silently never runs while the code still reads as if it is protected.
 */
final class CacheLock
{
    /**
     * Run a callback under a cache lock when the store supports locking.
     *
     * Falls back to running the callback unguarded, so correctness degrades to
     * "best effort" rather than to "never executes" on stores without locks.
     */
    public static function run(CacheRepository $cache, string $key, int $seconds, callable $callback, int $waitSeconds = 2): mixed
    {
        $store = method_exists($cache, 'getStore') ? $cache->getStore() : null;

        if ($store instanceof LockProvider) {
            return $cache->lock($key, $seconds)->block($waitSeconds, $callback);
        }

        return $callback();
    }

    /**
     * Atomically reserve one slot from a fixed-per-window counter.
     *
     * Seeding uses add() rather than get()+put() so a concurrent increment is
     * never overwritten, and an over-limit caller decrements back so the
     * counter reflects actual grants instead of attempted requests.
     *
     * @return bool true when a slot was granted, false when the window is full
     */
    public static function reserveSlot(CacheRepository $cache, string $key, int $max, int $windowSeconds): bool
    {
        return (bool) self::run($cache, $key . ':lock', 5, static function () use ($cache, $key, $max, $windowSeconds): bool {
            $cache->add($key, 0, $windowSeconds);
            $current = (int) $cache->increment($key);

            if ($current <= $max) {
                return true;
            }

            $cache->decrement($key);

            return false;
        }, 1);
    }
}
