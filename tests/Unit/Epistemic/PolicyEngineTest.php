<?php
declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Unit\Epistemic;

use Mixudev\SecurityDefense\Epistemic\DTO\ThreatAssessment;
use Mixudev\SecurityDefense\Epistemic\Policy\DecisionAction;
use Mixudev\SecurityDefense\Epistemic\Policy\PolicyEngine;
use Mixudev\SecurityDefense\Epistemic\ValueObjects\Confidence;
use Mixudev\SecurityDefense\Epistemic\ValueObjects\RiskScore;
use PHPUnit\Framework\TestCase;

class PolicyEngineTest extends TestCase
{
    private function assessment(float $risk): ThreatAssessment { return new ThreatAssessment(risk: RiskScore::from($risk), confidence: Confidence::from(0.7), hypotheses: [], evidence: []); }
    public function test_allow_when_low_risk(): void { $this->assertEquals(DecisionAction::ALLOW, (new PolicyEngine())->decide($this->assessment(0.0))->action); }
    public function test_monitor_at_0_35(): void { $this->assertEquals(DecisionAction::MONITOR, (new PolicyEngine())->decide($this->assessment(0.35))->action); }
    public function test_challenge_at_0_55(): void { $this->assertEquals(DecisionAction::CHALLENGE, (new PolicyEngine())->decide($this->assessment(0.55))->action); }
    public function test_quarantine_at_0_75(): void { $this->assertEquals(DecisionAction::QUARANTINE, (new PolicyEngine())->decide($this->assessment(0.75))->action); }
    public function test_block_at_0_90(): void { $this->assertEquals(DecisionAction::BLOCK, (new PolicyEngine())->decide($this->assessment(0.90))->action); }
    public function test_boundary_exactly_at_block_threshold(): void { $this->assertEquals(DecisionAction::BLOCK, (new PolicyEngine(blockThreshold: 0.85))->decide($this->assessment(0.85))->action); }
}
