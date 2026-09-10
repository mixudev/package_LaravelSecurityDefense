<?php
declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Unit\Epistemic;

use DateTimeImmutable;
use Mixudev\SecurityDefense\Epistemic\Belief\ThreatBelief;
use Mixudev\SecurityDefense\Epistemic\Belief\ThreatHypothesis;
use Mixudev\SecurityDefense\Epistemic\Engine\RiskEngine;
use Mixudev\SecurityDefense\Epistemic\Evidence\Evidence;
use Mixudev\SecurityDefense\Epistemic\ValueObjects\Confidence;
use Mixudev\SecurityDefense\Epistemic\ValueObjects\EvidenceType;
use Mixudev\SecurityDefense\Epistemic\ValueObjects\RiskScore;
use PHPUnit\Framework\TestCase;

class RiskEngineTest extends TestCase
{
    private function belief(array $supporting = [], array $contradicting = [], float $confidence = 0.8): ThreatBelief { return new ThreatBelief(ThreatHypothesis::ACCOUNT_COMPROMISE, Confidence::from($confidence), $supporting, $contradicting, new DateTimeImmutable()); }
    private function evidence(EvidenceType $type): Evidence { return new Evidence($type, 'test', new DateTimeImmutable(), Confidence::from(0.8)); }
    public function test_zero_evidence_risk_stays_at_current(): void { $result = (new RiskEngine())->calculate($this->belief([], [], 0.5), RiskScore::from(0.3)); $this->assertEqualsWithDelta(0.3, $result->value, 0.001); }
    public function test_all_supporting_increases_risk(): void { $result = (new RiskEngine())->calculate($this->belief([$this->evidence(EvidenceType::LOGIN_FAILED), $this->evidence(EvidenceType::NEW_DEVICE), $this->evidence(EvidenceType::OTP_FAILED)], [], 0.9), RiskScore::zero()); $this->assertGreaterThan(0.0, $result->value); }
    public function test_result_always_bounded(): void { $result = (new RiskEngine())->calculate($this->belief(array_fill(0, 10, $this->evidence(EvidenceType::LOGIN_FAILED)), [], 1.0), RiskScore::max()); $this->assertGreaterThanOrEqual(0.0, $result->value); $this->assertLessThanOrEqual(1.0, $result->value); }
    public function test_max_iterations_zero_returns_current(): void { $result = (new RiskEngine(maxIterations: 0))->calculate($this->belief([$this->evidence(EvidenceType::LOGIN_FAILED)], [], 0.9), RiskScore::from(0.4)); $this->assertEqualsWithDelta(0.4, $result->value, 0.0001); }
    public function test_non_convergence_returns_best_known(): void { $result = (new RiskEngine(epsilon: 1.0, maxIterations: 3))->calculate($this->belief([$this->evidence(EvidenceType::LOGIN_FAILED)], [], 0.8), RiskScore::from(0.5)); $this->assertGreaterThanOrEqual(0.0, $result->value); $this->assertLessThanOrEqual(1.0, $result->value); }
}
