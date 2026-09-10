<?php
declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Unit\Epistemic;

use Mixudev\SecurityDefense\DTO\SecurityEvent;
use Mixudev\SecurityDefense\DTO\SecurityThreat;
use Mixudev\SecurityDefense\Epistemic\Evidence\EvidenceBuilder;
use Mixudev\SecurityDefense\Epistemic\ValueObjects\EvidenceType;
use PHPUnit\Framework\TestCase;

class EvidenceBuilderTest extends TestCase
{
    public function test_from_security_event_known_type(): void
    {
        $event = new SecurityEvent('1.2.3.4', 'user1', 'LoginFailed');
        $e = EvidenceBuilder::fromSecurityEvent($event);
        $this->assertNotNull($e);
        $this->assertEquals(EvidenceType::LOGIN_FAILED, $e->type);
    }

    public function test_from_security_event_unknown_type_returns_null(): void
    {
        $event = new SecurityEvent('1.2.3.4', 'user1', 'SomeUnknownEvent');
        $e = EvidenceBuilder::fromSecurityEvent($event);
        $this->assertNull($e);
    }

    public function test_from_security_threat_brute_force(): void
    {
        $threat = new SecurityThreat('high', 'brute_force', 'fp1', [], 'brute_force');
        $e = EvidenceBuilder::fromSecurityThreat($threat);
        $this->assertNotNull($e);
        $this->assertEquals(EvidenceType::BRUTE_FORCE, $e->type);
    }

    public function test_from_security_threat_unknown_returns_null(): void
    {
        $threat = new SecurityThreat('low', 'some_custom_rule', 'fp2', [], 'custom');
        $e = EvidenceBuilder::fromSecurityThreat($threat);
        $this->assertNull($e);
    }

    public function test_reliability_is_valid_confidence(): void
    {
        $event = new SecurityEvent('1.2.3.4', 'user1', 'LoginFailed');
        $e = EvidenceBuilder::fromSecurityEvent($event);
        $this->assertNotNull($e);
        $this->assertGreaterThanOrEqual(0.0, $e->reliability->value);
        $this->assertLessThanOrEqual(1.0, $e->reliability->value);
    }
}
