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
use Mixudev\SecurityDefense\Epistemic\Contracts\AiEvidenceProviderInterface;
use Mixudev\SecurityDefense\Epistemic\Contracts\DecisionResponseAdapterInterface;
use Mixudev\SecurityDefense\Epistemic\Response\ResponseResult;
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

    public function test_response_runs_for_distinct_evidence_with_same_decision(): void
    {
        $calls = 0;
        $adapter = new class($calls) implements DecisionResponseAdapterInterface {
            public function __construct(private int &$calls) {}
            public function respond(\Mixudev\SecurityDefense\Epistemic\Policy\ThreatDecision $decision): ResponseResult
            {
                $this->calls++;
                return new ResponseResult(true, $decision->id());
            }
        };
        $analyzer = new EpistemicAnalyzer(new EpistemicEngine(), new RiskEngine(), new ThreatCorrelator(), new PolicyEngine(), new NullAiProvider(), ['response' => ['enabled' => true]], null, $adapter);
        $first = $analyzer->analyze(new AnalysisContext(evidence: [$this->makeEvidence(EvidenceType::LOGIN_FAILED)]));
        $second = $analyzer->analyze(new AnalysisContext(evidence: [$this->makeEvidence(EvidenceType::OTP_FAILED)]));

        $this->assertNotNull($first->decision());
        $this->assertNotNull($second->decision());
        $this->assertSame($first->decision()->id(), $second->decision()->id());
        $this->assertSame(2, $calls);
        $this->assertNotNull($analyzer->responseResult($second->decision()->id()));
    }

    public function test_adapter_exception_is_not_retried_automatically(): void
    {
        $calls = 0;
        $adapter = new class($calls) implements DecisionResponseAdapterInterface {
            public function __construct(private int &$calls) {}
            public function respond(\Mixudev\SecurityDefense\Epistemic\Policy\ThreatDecision $decision): ResponseResult
            {
                $this->calls++;
                throw new \RuntimeException('adapter transient failure');
            }
        };
        $analyzer = new EpistemicAnalyzer(
            new EpistemicEngine(),
            new RiskEngine(),
            new ThreatCorrelator(),
            new PolicyEngine(),
            new NullAiProvider(),
            ['response' => ['enabled' => true]],
            null,
            $adapter
        );

        $assessment = $analyzer->analyze(new AnalysisContext(evidence: [$this->makeEvidence(EvidenceType::LOGIN_FAILED)]));

        $this->assertNotNull($assessment->decision());
        $this->assertSame(1, $calls, 'Adapter must be invoked exactly once on failure; auto-retry can duplicate side effects.');
        $result = $analyzer->responseResult($assessment->decision()->id());
        $this->assertNotNull($result);
        $this->assertFalse($result->handled);
        $this->assertStringContainsString('Response adapter failed', (string) $result->error);
    }

    public function test_ai_evidence_alone_cannot_authorize_policy(): void
    {
        $ai = new class implements AiEvidenceProviderInterface {
            public function getEvidenceFor(AnalysisContext $context): array
            {
                return [new Evidence(EvidenceType::LOGIN_FAILED, 'ai:model', new DateTimeImmutable(), Confidence::from(1.0), ['provenance' => 'model'])];
            }
        };
        $analyzer = new EpistemicAnalyzer(new EpistemicEngine(), new RiskEngine(), new ThreatCorrelator(), new PolicyEngine(), $ai);

        $this->assertNull($analyzer->analyze(new AnalysisContext())->decision());
    }

    public function test_ai_cannot_complete_support_with_one_trusted_event(): void
    {
        $ai = new class implements AiEvidenceProviderInterface {
            public function getEvidenceFor(AnalysisContext $context): array
            {
                return [new Evidence(EvidenceType::NEW_DEVICE, 'ai:model', new DateTimeImmutable(), Confidence::from(1.0), ['provenance' => 'model'])];
            }
        };
        $analyzer = new EpistemicAnalyzer(new EpistemicEngine(), new RiskEngine(), new ThreatCorrelator(), new PolicyEngine(), $ai);

        $this->assertNull($analyzer->analyze(new AnalysisContext(evidence: [$this->makeEvidence(EvidenceType::LOGIN_FAILED)]))->decision());
    }

    public function test_ai_advisory_signal_remains_usable_with_enough_trusted_evidence(): void
    {
        $ai = new class implements AiEvidenceProviderInterface {
            public function getEvidenceFor(AnalysisContext $context): array
            {
                return [new Evidence(EvidenceType::NEW_DEVICE, 'ai:model', new DateTimeImmutable(), Confidence::from(1.0), ['provenance' => 'model'])];
            }
        };
        $analyzer = new EpistemicAnalyzer(new EpistemicEngine(), new RiskEngine(), new ThreatCorrelator(), new PolicyEngine(), $ai);
        $assessment = $analyzer->analyze(new AnalysisContext(evidence: [
            $this->makeEvidence(EvidenceType::LOGIN_FAILED),
            $this->makeEvidence(EvidenceType::OTP_FAILED),
        ]));

        $this->assertNotNull($assessment->decision());
        $this->assertNotEmpty($assessment->hypotheses());
    }

    public function test_malformed_events_are_skipped(): void
    {
        $assessment = $this->makeAnalyzer()->analyze(new AnalysisContext(events: [[], 'invalid', new SecurityEvent('1.2.3.4', 'user1', 'LoginFailed')]));

        $this->assertNotNull($assessment);
        $this->assertCount(1, $assessment->evidence());
    }

    public function test_future_direct_evidence_is_excluded(): void
    {
        $future = new Evidence(EvidenceType::LOGIN_FAILED, 'test', new DateTimeImmutable('+3600 seconds'), Confidence::from(0.8));
        $assessment = $this->makeAnalyzer()->analyze(new AnalysisContext(evidence: [$future]));

        $this->assertCount(0, $assessment->evidence());
    }

    public function test_ai_evidence_cannot_overwrite_trusted_evidence_with_same_id(): void
    {
        $trusted = $this->makeEvidence(EvidenceType::LOGIN_FAILED);
        $ai = new Evidence(EvidenceType::TRUSTED_DEVICE, 'ai:model', new DateTimeImmutable(), Confidence::from(1.0), ['provenance' => 'x'], $trusted->id);
        $provider = new class($ai) implements AiEvidenceProviderInterface {
            public function __construct(private mixed $evidence) {}
            public function getEvidenceFor(AnalysisContext $context): array { return [$this->evidence]; }
        };
        $analyzer = new EpistemicAnalyzer(new EpistemicEngine(), new RiskEngine(), new ThreatCorrelator(), new PolicyEngine(), $provider);
        $assessment = $analyzer->analyze(new AnalysisContext(evidence: [$trusted]));

        $this->assertCount(1, $assessment->evidence());
        $this->assertSame('test', $assessment->evidence()[0]->source);
    }

    public function test_ai_evidence_requiring_provenance_cannot_pose_as_trusted(): void
    {
        $ai = new class implements AiEvidenceProviderInterface {
            public function getEvidenceFor(AnalysisContext $context): array
            {
                return [new Evidence(EvidenceType::LOGIN_FAILED, 'ai:model', new DateTimeImmutable(), Confidence::from(1.0))];
            }
        };
        $analyzer = new EpistemicAnalyzer(new EpistemicEngine(), new RiskEngine(), new ThreatCorrelator(), new PolicyEngine(), $ai, ['ai' => ['max_evidence' => 10, 'max_metadata_bytes' => 4096, 'allowed_future_seconds' => 60]]);
        $assessment = $analyzer->analyze(new AnalysisContext(evidence: []));

        $this->assertCount(0, $assessment->evidence());
    }
}
