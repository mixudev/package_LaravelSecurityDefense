<?php
declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Unit\Epistemic;

use DateTimeImmutable;
use Mixudev\SecurityDefense\Epistemic\Engine\EpistemicEngine;
use Mixudev\SecurityDefense\Epistemic\Evidence\Evidence;
use Mixudev\SecurityDefense\Epistemic\ValueObjects\Confidence;
use Mixudev\SecurityDefense\Epistemic\ValueObjects\EvidenceType;
use PHPUnit\Framework\TestCase;

class EpistemicEngineTest extends TestCase
{
    private function makeSupportingEvidence(): Evidence
    {
        return new Evidence(EvidenceType::LOGIN_FAILED, 'test', new DateTimeImmutable(), Confidence::from(0.9));
    }
    private function makeContradictingEvidence(): Evidence
    {
        return new Evidence(EvidenceType::TRUSTED_DEVICE, 'test', new DateTimeImmutable(), Confidence::from(0.9));
    }
    public function test_no_evidence_returns_prior(): void { $c = (new EpistemicEngine())->computeConfidence([], []); $this->assertEqualsWithDelta(0.5, $c->value, 0.001); }
    public function test_supporting_evidence_increases_confidence(): void { $c = (new EpistemicEngine())->computeConfidence([$this->makeSupportingEvidence()], []); $this->assertGreaterThan(0.5, $c->value); }
    public function test_contradicting_evidence_decreases_confidence(): void { $c = (new EpistemicEngine())->computeConfidence([], [$this->makeContradictingEvidence()]); $this->assertLessThan(0.5, $c->value); }
    public function test_contradicting_with_supporting_no_exception(): void { $c = (new EpistemicEngine())->computeConfidence([$this->makeSupportingEvidence(), $this->makeSupportingEvidence()], [$this->makeContradictingEvidence()]); $this->assertGreaterThanOrEqual(0.0, $c->value); $this->assertLessThanOrEqual(1.0, $c->value); }
    public function test_confidence_always_bounded(): void { $c = (new EpistemicEngine())->computeConfidence(array_fill(0, 20, $this->makeSupportingEvidence()), []); $this->assertGreaterThanOrEqual(0.0, $c->value); $this->assertLessThanOrEqual(1.0, $c->value); }
    public function test_stale_evidence_has_minimal_effect(): void { $old = new Evidence(EvidenceType::LOGIN_FAILED, 'test', new DateTimeImmutable('-7200 seconds'), Confidence::from(0.9)); $c = (new EpistemicEngine(evidenceTtlSeconds: 900.0))->computeConfidence([$old], []); $this->assertLessThan(0.52, $c->value); }
}
