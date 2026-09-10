<?php
declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Unit\Epistemic;

use Mixudev\SecurityDefense\DTO\SecurityEvent;
use Mixudev\SecurityDefense\DTO\SecurityThreat;
use Mixudev\SecurityDefense\Epistemic\Evidence\EvidenceBuilder;
use DateTimeImmutable;
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

    public function test_malformed_timestamp_returns_null(): void
    {
        $event = new SecurityEvent('1.2.3.4', 'user1', 'LoginFailed', 'not-a-timestamp');
        $this->assertNull(EvidenceBuilder::fromSecurityEvent($event));
    }

    public function test_future_timestamp_beyond_skew_returns_null(): void
    {
        $now = new DateTimeImmutable('2026-01-01T00:00:00+00:00');
        $event = new SecurityEvent('1.2.3.4', 'user1', 'LoginFailed', '2026-01-01T00:01:01+00:00');
        $this->assertNull(EvidenceBuilder::fromSecurityEvent($event, 60, $now));
    }

    public function test_caller_event_id_is_preserved_from_metadata(): void
    {
        $event = new SecurityEvent('1.2.3.4', 'user1', 'LoginFailed', '2026-01-01T00:00:00+00:00', '', ['id' => 'event-123']);
        $e = EvidenceBuilder::fromSecurityEvent($event);
        $this->assertNotNull($e);
        $this->assertSame('event-123', $e->id);
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
