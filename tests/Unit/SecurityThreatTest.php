<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Unit;

use Mixudev\SecurityDefense\DTO\SecurityThreat;
use PHPUnit\Framework\TestCase;

class SecurityThreatTest extends TestCase
{
    public function test_it_creates_threat_with_sanitized_metadata_and_deterministic_fingerprint(): void
    {
        $threat = new SecurityThreat(
            severity: 'high',
            threatType: 'brute_force',
            fingerprint: '',
            metadata: [
                'target' => 'admin',
                'secret_info' => 'do-not-leak',
            ],
            ruleIdentifier: 'brute_force'
        );

        $this->assertEquals('high', $threat->severity);
        $this->assertEquals('brute_force', $threat->threatType);
        $this->assertNotEmpty($threat->fingerprint);
        $this->assertEquals(64, strlen($threat->fingerprint)); // SHA-256
        $this->assertEquals('[REDACTED]', $threat->metadata['secret_info']);
        $this->assertEquals('admin', $threat->metadata['target']);
    }

    public function test_it_normalizes_invalid_severity_to_medium(): void
    {
        $threat = new SecurityThreat(
            severity: 'invalid_severity',
            threatType: 'custom_threat',
            fingerprint: 'custom_fp'
        );

        $this->assertEquals('medium', $threat->severity);
    }
}
