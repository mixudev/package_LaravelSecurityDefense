<?php
declare(strict_types=1);

namespace Mixudev\SecurityDefense\Epistemic\Policy;
use Mixudev\SecurityDefense\Epistemic\Contracts\PolicyEngineInterface;
use Mixudev\SecurityDefense\Epistemic\DTO\ThreatAssessment;

final class PolicyEngine implements PolicyEngineInterface
{
    private readonly float $blockThreshold;
    private readonly float $quarantineThreshold;
    private readonly float $challengeThreshold;
    private readonly float $monitorThreshold;

    public function __construct(float $blockThreshold = 0.85, float $quarantineThreshold = 0.70, float $challengeThreshold = 0.50, float $monitorThreshold = 0.30)
    {
        $thresholds = [$monitorThreshold, $challengeThreshold, $quarantineThreshold, $blockThreshold];
        if (array_filter($thresholds, fn (float $v): bool => !is_finite($v) || $v < 0.0 || $v > 1.0) !== []) throw new \InvalidArgumentException('Policy thresholds must be finite and within [0, 1].');
        if ($monitorThreshold > $challengeThreshold || $challengeThreshold > $quarantineThreshold || $quarantineThreshold > $blockThreshold) throw new \InvalidArgumentException('Policy thresholds must be ordered monitor <= challenge <= quarantine <= block.');
        $this->blockThreshold = $blockThreshold; $this->quarantineThreshold = $quarantineThreshold; $this->challengeThreshold = $challengeThreshold; $this->monitorThreshold = $monitorThreshold;
    }

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
