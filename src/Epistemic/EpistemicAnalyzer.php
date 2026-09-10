<?php
declare(strict_types=1);

namespace Mixudev\SecurityDefense\Epistemic;

use Mixudev\SecurityDefense\Epistemic\Contracts\AiEvidenceProviderInterface;
use Mixudev\SecurityDefense\Epistemic\Contracts\PolicyEngineInterface;
use Mixudev\SecurityDefense\Epistemic\Correlation\ThreatCorrelator;
use Mixudev\SecurityDefense\Epistemic\DTO\AnalysisContext;
use Mixudev\SecurityDefense\Epistemic\DTO\ThreatAssessment;
use Mixudev\SecurityDefense\Epistemic\Engine\EpistemicEngine;
use Mixudev\SecurityDefense\Epistemic\Engine\RiskEngine;
use Mixudev\SecurityDefense\Epistemic\Evidence\EvidenceBuilder;
use Mixudev\SecurityDefense\Epistemic\Evidence\EvidenceCollection;
use Mixudev\SecurityDefense\Epistemic\ValueObjects\Confidence;
use Mixudev\SecurityDefense\Epistemic\ValueObjects\RiskScore;

/** Full epistemic analysis pipeline orchestrator. */
final class EpistemicAnalyzer
{
    public function __construct(
        private readonly EpistemicEngine $epistemicEngine,
        private readonly RiskEngine $riskEngine,
        private readonly ThreatCorrelator $correlator,
        private readonly PolicyEngineInterface $policyEngine,
        private readonly AiEvidenceProviderInterface $aiProvider,
        private readonly array $config = [],
    ) {}

    public function analyze(AnalysisContext $context): ThreatAssessment
    {
        $collection = new EvidenceCollection();
        foreach ($context->events as $event) {
            if (($e = EvidenceBuilder::fromSecurityEvent($event)) !== null) $collection->add($e);
        }
        foreach ($context->evidence as $e) $collection->add($e);
        foreach ($this->aiProvider->getEvidenceFor($context) as $e) $collection->add($e);

        $beliefs = $this->correlator->correlate($collection->all(), $context->windowSeconds);
        $computedBeliefs = [];
        $maxRisk = RiskScore::zero();
        foreach ($beliefs as $belief) {
            $belief = $belief->withConfidence($this->epistemicEngine->computeConfidence(
                $belief->supportingEvidence, $belief->contradictingEvidence
            ));
            $risk = $this->riskEngine->calculate($belief, RiskScore::zero(), $this->config['risk'] ?? []);
            if ($risk->isHigherThan($maxRisk)) $maxRisk = $risk;
            $computedBeliefs[] = $belief;
        }
        $aggConfidence = count($computedBeliefs) > 0
            ? Confidence::from(array_sum(array_map(fn($b) => $b->confidence->toFloat(), $computedBeliefs)) / count($computedBeliefs))
            : Confidence::from(0.0);
        $assessment = new ThreatAssessment(risk: $maxRisk, confidence: $aggConfidence, hypotheses: $computedBeliefs, evidence: $collection->all());
        return new ThreatAssessment(risk: $maxRisk, confidence: $aggConfidence, hypotheses: $computedBeliefs, evidence: $collection->all(), decision: $this->policyEngine->decide($assessment));
    }
}
