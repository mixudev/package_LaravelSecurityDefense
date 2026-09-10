<?php
declare(strict_types=1);

namespace Mixudev\SecurityDefense\Epistemic\Policy;

use Mixudev\SecurityDefense\Epistemic\Contracts\PolicyEngineInterface;
use Mixudev\SecurityDefense\Epistemic\DTO\ThreatAssessment;

final class PolicyEngine implements PolicyEngineInterface
{
    public function __construct(private readonly float $blockThreshold = 0.85, private readonly float $quarantineThreshold = 0.70, private readonly float $challengeThreshold = 0.50, private readonly float $monitorThreshold = 0.30) {}

    public function decide(ThreatAssessment $assessment): ThreatDecision
    {
        $risk = $assessment->risk->toFloat();
        return match (true) {
            $risk >= $this->blockThreshold => new ThreatDecision(DecisionAction::BLOCK, 'Risk score above block threshold', ['risk' => $risk]),
            $risk >= $this->quarantineThreshold => new ThreatDecision(DecisionAction::QUARANTINE, 'Risk score above quarantine threshold', ['risk' => $risk]),
            $risk >= $this->challengeThreshold => new ThreatDecision(DecisionAction::CHALLENGE, 'Risk score above challenge threshold', ['risk' => $risk]),
            $risk >= $this->monitorThreshold => new ThreatDecision(DecisionAction::MONITOR, 'Risk score above monitor threshold', ['risk' => $risk]),
            default => new ThreatDecision(DecisionAction::ALLOW, 'Risk score below all thresholds', ['risk' => $risk]),
        };
    }
}
