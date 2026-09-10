<?php
declare(strict_types=1);

namespace Mixudev\SecurityDefense\Epistemic\DTO;

use Mixudev\SecurityDefense\Epistemic\Belief\ThreatBelief;
use Mixudev\SecurityDefense\Epistemic\Policy\ThreatDecision;
use Mixudev\SecurityDefense\Epistemic\ValueObjects\Confidence;
use Mixudev\SecurityDefense\Epistemic\ValueObjects\RiskScore;

final class ThreatAssessment
{
    public function __construct(public readonly RiskScore $risk, public readonly Confidence $confidence, public readonly array $hypotheses, public readonly array $evidence, public readonly ?ThreatDecision $decision = null) {}
    public function risk(): RiskScore { return $this->risk; }
    public function confidence(): Confidence { return $this->confidence; }
    public function hypotheses(): array { return $this->hypotheses; }
    public function evidence(): array { return $this->evidence; }
    public function decision(): ?ThreatDecision { return $this->decision; }
    public function toArray(): array { return ['risk' => $this->risk->toFloat(), 'confidence' => $this->confidence->toFloat(), 'hypotheses' => array_map(fn(ThreatBelief $b) => $b->toArray(), $this->hypotheses), 'evidence_count' => count($this->evidence), 'decision' => $this->decision?->action->value]; }
}
