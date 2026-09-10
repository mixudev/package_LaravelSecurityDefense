<?php
declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Unit\Epistemic;

use DateTimeImmutable;
use Mixudev\SecurityDefense\Epistemic\Belief\ThreatBelief;
use Mixudev\SecurityDefense\Epistemic\Belief\ThreatHypothesis;
use Mixudev\SecurityDefense\Epistemic\Evidence\Evidence;
use Mixudev\SecurityDefense\Epistemic\ValueObjects\Confidence;
use Mixudev\SecurityDefense\Epistemic\ValueObjects\EvidenceType;
use PHPUnit\Framework\TestCase;

class ThreatBeliefTest extends TestCase
{
    private function makeEvidence(EvidenceType $type, string $id): Evidence
    {
        return new Evidence($type, 'test', new DateTimeImmutable(), Confidence::from(0.8), [], $id);
    }

    private function makeBelief(): ThreatBelief
    {
        return new ThreatBelief(
            hypothesis: ThreatHypothesis::ACCOUNT_COMPROMISE,
            confidence: Confidence::from(0.5),
            supportingEvidence: [],
            contradictingEvidence: [],
            updatedAt: new DateTimeImmutable(),
        );
    }

    public function test_with_confidence_returns_new_instance(): void
    {
        $b1 = $this->makeBelief();
        $b2 = $b1->withConfidence(Confidence::from(0.9));
        $this->assertNotSame($b1, $b2);
        $this->assertEqualsWithDelta(0.5, $b1->confidence->value, 0.000001);
        $this->assertEqualsWithDelta(0.9, $b2->confidence->value, 0.000001);
    }

    public function test_with_added_supporting(): void
    {
        $b  = $this->makeBelief();
        $e  = $this->makeEvidence(EvidenceType::NEW_DEVICE, 'ev1');
        $b2 = $b->withAddedSupporting($e);
        $this->assertCount(1, $b2->supportingEvidence);
        $this->assertCount(0, $b->supportingEvidence);
    }

    public function test_has_contradiction_true(): void
    {
        $b = $this->makeBelief()
            ->withAddedSupporting($this->makeEvidence(EvidenceType::LOGIN_FAILED, 'a'))
            ->withAddedContradicting($this->makeEvidence(EvidenceType::TRUSTED_DEVICE, 'b'));
        $this->assertTrue($b->hasContradiction());
    }

    public function test_has_contradiction_false_when_only_supporting(): void
    {
        $b = $this->makeBelief()
            ->withAddedSupporting($this->makeEvidence(EvidenceType::LOGIN_FAILED, 'a'));
        $this->assertFalse($b->hasContradiction());
    }

    public function test_to_array_keys(): void
    {
        $arr = $this->makeBelief()->toArray();
        $this->assertArrayHasKey('hypothesis', $arr);
        $this->assertArrayHasKey('confidence', $arr);
        $this->assertArrayHasKey('supporting', $arr);
        $this->assertArrayHasKey('contradicting', $arr);
        $this->assertArrayHasKey('updated_at', $arr);
    }
}
