<?php
declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature\Epistemic;

use DateTimeImmutable;
use Mixudev\SecurityDefense\DTO\SecurityEvent;
use Mixudev\SecurityDefense\Epistemic\AI\NullAiProvider;
use Mixudev\SecurityDefense\Epistemic\Correlation\ThreatCorrelator;
use Mixudev\SecurityDefense\Epistemic\DTO\AnalysisContext;
use Mixudev\SecurityDefense\Epistemic\Engine\EpistemicEngine;
use Mixudev\SecurityDefense\Epistemic\Engine\RiskEngine;
use Mixudev\SecurityDefense\Epistemic\EpistemicAnalyzer;
use Mixudev\SecurityDefense\Epistemic\Evidence\Evidence;
use Mixudev\SecurityDefense\Epistemic\Policy\PolicyEngine;
use Mixudev\SecurityDefense\Epistemic\Policy\DecisionAction;
use Mixudev\SecurityDefense\Epistemic\ValueObjects\Confidence;
use Mixudev\SecurityDefense\Epistemic\ValueObjects\EvidenceType;
use Mixudev\SecurityDefense\Tests\TestCase;

class EpistemicAnalyzerTest extends TestCase
{
    private function makeAnalyzer(): EpistemicAnalyzer
    {
        return new EpistemicAnalyzer(
            epistemicEngine: new EpistemicEngine(),
            riskEngine: new RiskEngine(),
            correlator: new ThreatCorrelator(),
            policyEngine: new PolicyEngine(),
            aiProvider: new NullAiProvider(),
        );
    }

    private function makeEvidence(EvidenceType $type): Evidence
    {
        return new Evidence($type, 'test', new DateTimeImmutable(), Confidence::from(0.8));
    }

    public function test_empty_context_returns_zero_risk_allow(): void
    {
        $analyzer = $this->makeAnalyzer();
        $assessment = $analyzer->analyze(new AnalysisContext());
        $this->assertEquals(0.0, $assessment->risk->toFloat());
        $this->assertEquals(DecisionAction::ALLOW, $assessment->decision?->action);
    }

    public function test_account_compromise_signals_increase_risk(): void
    {
        $analyzer = $this->makeAnalyzer();
        $context = new AnalysisContext(
            evidence: [
                $this->makeEvidence(EvidenceType::LOGIN_FAILED),
                $this->makeEvidence(EvidenceType::LOGIN_FAILED),
                $this->makeEvidence(EvidenceType::NEW_DEVICE),
                $this->makeEvidence(EvidenceType::OTP_FAILED),
            ]
        );
        $assessment = $analyzer->analyze($context);
        $this->assertGreaterThan(0.0, $assessment->risk->toFloat());
        $this->assertNotEmpty($assessment->hypotheses());
    }

    public function test_contradicting_evidence_does_not_crash(): void
    {
        $analyzer = $this->makeAnalyzer();
        $context = new AnalysisContext(
            evidence: [
                $this->makeEvidence(EvidenceType::LOGIN_FAILED),
                $this->makeEvidence(EvidenceType::NEW_DEVICE),
                $this->makeEvidence(EvidenceType::TRUSTED_DEVICE),
            ]
        );
        $assessment = $analyzer->analyze($context);
        $this->assertNotNull($assessment);
        $this->assertGreaterThanOrEqual(0.0, $assessment->risk->toFloat());
    }

    public function test_duplicate_events_deduplicated(): void
    {
        $analyzer = $this->makeAnalyzer();
        $event1 = new SecurityEvent('1.2.3.4', 'user1', 'LoginFailed', '2026-01-01T10:30:00+00:00');
        $event2 = new SecurityEvent('1.2.3.4', 'user1', 'LoginFailed', '2026-01-01T10:30:00+00:00');
        $context = new AnalysisContext(events: [$event1, $event2]);
        $assessment = $analyzer->analyze($context);
        $this->assertLessThanOrEqual(1, count($assessment->evidence()));
    }

    public function test_assessment_has_decision(): void
    {
        $analyzer = $this->makeAnalyzer();
        $assessment = $analyzer->analyze(new AnalysisContext());
        $this->assertNotNull($assessment->decision());
    }

    public function test_to_array_structure(): void
    {
        $analyzer = $this->makeAnalyzer();
        $assessment = $analyzer->analyze(new AnalysisContext());
        $arr = $assessment->toArray();
        $this->assertArrayHasKey('risk', $arr);
        $this->assertArrayHasKey('confidence', $arr);
        $this->assertArrayHasKey('hypotheses', $arr);
        $this->assertArrayHasKey('evidence_count', $arr);
        $this->assertArrayHasKey('decision', $arr);
    }
}
