<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Unit;

use Illuminate\Support\Facades\Cache;
use Mixudev\SecurityDefense\DTO\SecurityThreat;
use Mixudev\SecurityDefense\Services\ThreatScoringEngine;
use Mixudev\SecurityDefense\Tests\TestCase;

/**
 * Regression: ThreatScoringEngine seeded its window TTL with put() AFTER increment().
 *
 * Code under test (src/Services/ThreatScoringEngine.php:105-110):
 *     $totalScore = (int) $cache->increment($counterKey, $weight);
 *     if ($totalScore === $weight) {
 *         $cache->put($counterKey, $weight, $window);
 *     }
 *
 * The guard "$totalScore === $weight" only holds for the very first request.
 * Under concurrency, request A can increment 0->35 (guard true) and request B
 * can increment 35->55 BEFORE request A reaches the put(), so A stomps the
 * counter back down to 35 and silently discards B's threat weight.
 *
 * The correct pattern is add($counterKey, 0, $window) BEFORE increment(), which
 * sets the TTL on first touch and can never overwrite a later increment.
 */
final class ThreatScoringEngineSeedRaceTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        config()->set('security-defense.enabled', true);
        config()->set('security-defense.cache_store', 'array');
        config()->set('security-defense.detection.scoring.enabled', true);
        config()->set('security-defense.detection.scoring.window', 900);
        config()->set('security-defense.detection.scoring.threshold', 1000);
        Cache::forgetDriver();
    }

    private function threat(string $type, string $severity, string $ip): SecurityThreat
    {
        return new SecurityThreat($severity, $type, 'fp-' . $type, ['ip' => $ip]);
    }

    /**
     * A sequential pass cannot lose weight even under the old code, because
     * $totalScore === $weight is true exactly once (on the first request).
     * This test locks in the CORRECT behaviour so the fix is observable: the
     * counter must always equal the sum of weights.
     */
    public function test_counter_equals_sum_of_all_weights(): void
    {
        $engine = app(ThreatScoringEngine::class);
        $ip = '198.51.100.200';

        // high=35, medium=20, low=10, high=35
        $engine->recordThreat($this->threat('sqli', 'high', $ip));
        $engine->recordThreat($this->threat('recon', 'medium', $ip));
        $engine->recordThreat($this->threat('ua_anomaly', 'low', $ip));
        $engine->recordThreat($this->threat('header', 'high', $ip));

        self::assertSame(100, $engine->getScore($ip), 'Score counter lost accumulated threat weight.');
    }

    /**
     * The counter key must carry a non-null expiry so it cannot live forever.
     * Under the old put()-after-increment code, the key seeded by increment()
     * on a missing key would use forever() and the subsequent put() could be
     * skipped if the guard did not fire.
     */
    public function test_counter_key_always_has_an_expiry(): void
    {
        $engine = app(ThreatScoringEngine::class);
        $ip = '198.51.100.201';

        $engine->recordThreat($this->threat('sqli', 'high', $ip));

        // Confirm the score landed via the public API.
        self::assertSame(35, $engine->getScore($ip), 'Score did not persist via the counter.');

        $store = Cache::store('array')->getStore();
        $prop = new \ReflectionProperty(\Illuminate\Cache\ArrayStore::class, 'storage');
        $prop->setAccessible(true);
        $storage = $prop->getValue($store);

        // Find the key holding the integer score 35.
        $found = null;
        foreach ($storage as $key => $entry) {
            if (($entry['value'] ?? null) === 35 || @unserialize($entry['value'] ?? '') === 35) {
                $found = $key;
                break;
            }
        }

        self::assertNotNull($found, 'Counter key missing after first threat.');
        self::assertNotNull(
            $storage[$found]['expiresAt'] ?? null,
            'Scoring counter has no TTL: it accumulates forever for that target.'
        );
    }
}
