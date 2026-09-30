<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Unit;

use Illuminate\Support\Facades\Cache;
use Mixudev\SecurityDefense\DTO\SecurityThreat;
use Mixudev\SecurityDefense\Services\ThreatScoringEngine;
use Mixudev\SecurityDefense\Tests\TestCase;

/**
 * Regression: when `max_records = 0` (disable records retention / metadata-free mode),
 * `array_slice($records, -$maxRecords)` became `array_slice($records, 0)` which in
 * PHP returns the ENTIRE array instead of an empty one.
 *
 * Setting `max_records = 0` therefore defeated retention limiting completely,
 * retaining every record indefinitely in the cache.
 */
final class ThreatScoringEngineZeroRecordsTest extends TestCase
{
    public function test_zero_max_records_retains_no_records(): void
    {
        config(['security-defense.detection.scoring.max_records' => 0]);
        config(['security-defense.detection.scoring.enabled' => true]);

        $engine = new ThreatScoringEngine(Cache::store('array'));

        for ($i = 0; $i < 5; $i++) {
            $engine->recordThreat(new SecurityThreat(
                severity: 'low',
                threatType: 'test_probe',
                fingerprint: 'fp-' . $i,
                metadata: ['ip' => '192.0.2.1']
            ));
        }

        $recordsKey = 'security_defense:score:' . md5('192.0.2.1');
        $stored = (array) Cache::store('array')->get($recordsKey, []);

        self::assertEmpty(
            $stored,
            'max_records = 0 retained records in the cache because array_slice($x, -0) '
            . 'returns the full array in PHP'
        );
    }
}
