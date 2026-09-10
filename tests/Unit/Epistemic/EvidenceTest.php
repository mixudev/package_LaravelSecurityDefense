<?php
declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Unit\Epistemic;

use DateTimeImmutable;
use Mixudev\SecurityDefense\Epistemic\Evidence\Evidence;
use Mixudev\SecurityDefense\Epistemic\ValueObjects\Confidence;
use Mixudev\SecurityDefense\Epistemic\ValueObjects\EvidenceType;
use PHPUnit\Framework\TestCase;

class EvidenceTest extends TestCase
{
    private function make(EvidenceType $type = EvidenceType::LOGIN_FAILED, string $source = 'test', ?DateTimeImmutable $at = null): Evidence
    {
        return new Evidence($type, $source, $at ?? new DateTimeImmutable(), Confidence::from(0.8));
    }

    public function test_freshness_when_new(): void
    {
        $e = $this->make();
        $this->assertEqualsWithDelta(1.0, $e->freshness(900, new DateTimeImmutable()), 0.01);
    }

    public function test_freshness_zero_when_expired(): void
    {
        $old = new DateTimeImmutable('-1000 seconds');
        $e   = $this->make(EvidenceType::LOGIN_FAILED, 'test', $old);
        $this->assertEquals(0.0, $e->freshness(900));
    }

    public function test_freshness_never_negative(): void
    {
        $old = new DateTimeImmutable('-999999 seconds');
        $e   = $this->make(EvidenceType::LOGIN_FAILED, 'test', $old);
        $this->assertGreaterThanOrEqual(0.0, $e->freshness(900));
    }

    public function test_id_deterministic_same_minute(): void
    {
        $at = new DateTimeImmutable('2026-01-01 10:30:00');
        $e1 = new Evidence(EvidenceType::OTP_FAILED, 'rule', $at, Confidence::from(0.9));
        $e2 = new Evidence(EvidenceType::OTP_FAILED, 'rule', $at, Confidence::from(0.5));
        $this->assertEquals($e1->id, $e2->id);
    }

    public function test_id_differs_for_different_type(): void
    {
        $at = new DateTimeImmutable('2026-01-01 10:30:00');
        $e1 = new Evidence(EvidenceType::OTP_FAILED, 'rule', $at, Confidence::from(0.9));
        $e2 = new Evidence(EvidenceType::NEW_DEVICE, 'rule', $at, Confidence::from(0.9));
        $this->assertNotEquals($e1->id, $e2->id);
    }

    public function test_trusted_device_is_not_threat_supporting(): void
    {
        $e = $this->make(EvidenceType::TRUSTED_DEVICE);
        $this->assertFalse($e->isThreatSupporting());
    }

    public function test_login_failed_is_threat_supporting(): void
    {
        $e = $this->make(EvidenceType::LOGIN_FAILED);
        $this->assertTrue($e->isThreatSupporting());
    }
}
