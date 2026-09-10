<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Unit;

use Mixudev\SecurityDefense\DTO\SecurityThreat;
use Mixudev\SecurityDefense\Services\AlertDeduplicator;
use Mixudev\SecurityDefense\Tests\TestCase;

class AlertDeduplicatorTest extends TestCase
{
    public function test_atomic_claim_suppresses_duplicate_across_instances(): void
    {
        $cache = app('cache')->store('array');
        $first = new AlertDeduplicator($cache);
        $second = new AlertDeduplicator($cache);
        $threat = new SecurityThreat('high', 'brute_force', 'atomic-fingerprint');

        $this->assertTrue($first->shouldAlert($threat));
        $this->assertFalse($second->shouldAlert($threat));
    }

    public function test_it_deduplicates_identical_threat_fingerprints(): void
    {
        $deduplicator = app(AlertDeduplicator::class);

        $threat = new SecurityThreat(
            severity: 'high',
            threatType: 'brute_force',
            fingerprint: 'test-fingerprint-12345',
            metadata: ['target' => 'admin']
        );

        // Initial check: should alert
        $this->assertTrue($deduplicator->shouldAlert($threat));

        // Record threat in window
        $deduplicator->record($threat);

        // Second check within window: should be suppressed
        $this->assertFalse($deduplicator->shouldAlert($threat));

        // Forget fingerprint: should allow alerting again
        $deduplicator->forget($threat->fingerprint);
        $this->assertTrue($deduplicator->shouldAlert($threat));
    }
}
