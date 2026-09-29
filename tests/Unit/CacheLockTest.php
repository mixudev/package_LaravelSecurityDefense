<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Unit;

use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Repository;
use Mixudev\SecurityDefense\Support\CacheLock;
use Mixudev\SecurityDefense\Tests\TestCase;

final class CacheLockTest extends TestCase
{
    public function test_run_executes_the_callback_on_a_locking_store(): void
    {
        $cache = new Repository(new ArrayStore());

        $result = CacheLock::run($cache, 'k', 5, static fn (): string => 'ran');

        $this->assertSame('ran', $result);
    }

    public function test_run_still_executes_when_the_store_cannot_lock(): void
    {
        // A store that does not implement LockProvider: the helper must degrade
        // to running the callback, not to skipping the protected work entirely.
        $store = new class () implements \Illuminate\Contracts\Cache\Store {
            /** @var array<string, mixed> */
            public array $storage = [];

            public function get($key) { return $this->storage[$key] ?? null; }

            public function many(array $keys) { return []; }

            public function put($key, $value, $seconds) { $this->storage[$key] = $value; return true; }

            public function putMany(array $values, $seconds) { return true; }

            public function increment($key, $value = 1)
            {
                $current = (int) ($this->storage[$key] ?? 0) + $value;
                $this->storage[$key] = $current;

                return $current;
            }

            public function decrement($key, $value = 1) { return $this->increment($key, -$value); }

            public function forever($key, $value) { $this->storage[$key] = $value; return true; }

            public function forget($key) { unset($this->storage[$key]); return true; }

            public function flush() { $this->storage = []; return true; }

            public function getPrefix() { return ''; }
        };

        $this->assertFalse($store instanceof \Illuminate\Contracts\Cache\LockProvider);

        $cache = new Repository($store);
        $this->assertSame('ran', CacheLock::run($cache, 'k', 5, static fn (): string => 'ran'));
    }

    public function test_reserve_slot_grants_exactly_max_then_refuses(): void
    {
        $cache = new Repository(new ArrayStore());
        $granted = 0;

        for ($i = 0; $i < 10; $i++) {
            if (CacheLock::reserveSlot($cache, 'cap', 3, 60)) {
                $granted++;
            }
        }

        $this->assertSame(3, $granted, 'The cap must hold no matter how many callers ask.');
    }

    public function test_reserve_slot_counter_reflects_grants_not_attempts(): void
    {
        $cache = new Repository(new ArrayStore());

        CacheLock::reserveSlot($cache, 'cap2', 2, 60);
        CacheLock::reserveSlot($cache, 'cap2', 2, 60);
        for ($i = 0; $i < 5; $i++) {
            CacheLock::reserveSlot($cache, 'cap2', 2, 60);
        }

        $this->assertSame(2, (int) $cache->get('cap2'));
    }

    public function test_reserve_slot_seeds_ttl_only_once(): void
    {
        $cache = new Repository(new ArrayStore());

        CacheLock::reserveSlot($cache, 'cap3', 5, 60);
        CacheLock::reserveSlot($cache, 'cap3', 5, 60);

        // add() must not have reset the counter back to 0 on the second call.
        $this->assertSame(2, (int) $cache->get('cap3'));
    }
}
