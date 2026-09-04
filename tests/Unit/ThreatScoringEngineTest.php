<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Unit;

use Mixudev\SecurityDefense\DTO\SecurityThreat;
use Mixudev\SecurityDefense\Services\ThreatScoringEngine;
use Mixudev\SecurityDefense\Tests\TestCase;

class ThreatScoringEngineTest extends TestCase
{
    public function test_it_aggregates_threat_scores_and_triggers_compound_threat(): void
    {
        config()->set('security-defense.detection.scoring.enabled', true);
        config()->set('security-defense.detection.scoring.threshold', 100);
        config()->set('security-defense.detection.scoring.weights', [
            'rate_limit_bypass' => 30,
            'brute_force' => 40,
            'payload_injection' => 50,
        ]);

        $engine = app(ThreatScoringEngine::class);
        $targetIp = '198.51.100.77';

        // Attack 1: Rate limit bypass (30 pts)
        $threat1 = new SecurityThreat(
            severity: 'medium',
            threatType: 'rate_limit_bypass',
            fingerprint: 'fp1',
            metadata: ['ip' => $targetIp]
        );
        $compound1 = $engine->recordThreat($threat1);
        $this->assertNull($compound1); // Total: 30 < 100
        $this->assertEquals(30, $engine->getScore($targetIp));

        // Attack 2: Brute force (40 pts)
        $threat2 = new SecurityThreat(
            severity: 'high',
            threatType: 'brute_force',
            fingerprint: 'fp2',
            metadata: ['ip' => $targetIp]
        );
        $compound2 = $engine->recordThreat($threat2);
        $this->assertNull($compound2); // Total: 70 < 100
        $this->assertEquals(70, $engine->getScore($targetIp));

        // Attack 3: Payload injection (50 pts) -> Crosses threshold: 120 >= 100
        $threat3 = new SecurityThreat(
            severity: 'critical',
            threatType: 'payload_injection',
            fingerprint: 'fp3',
            metadata: ['ip' => $targetIp]
        );
        $compound3 = $engine->recordThreat($threat3);

        $this->assertNotNull($compound3);
        $this->assertEquals('compound_threat', $compound3->threatType);
        $this->assertEquals('critical', $compound3->severity);
        $this->assertEquals($targetIp, $compound3->metadata['target']);
        $this->assertGreaterThanOrEqual(100, $compound3->metadata['aggregate_score']);
        $this->assertContains('rate_limit_bypass', $compound3->metadata['involved_threats']);
        $this->assertContains('brute_force', $compound3->metadata['involved_threats']);
        $this->assertContains('payload_injection', $compound3->metadata['involved_threats']);
    }
}
