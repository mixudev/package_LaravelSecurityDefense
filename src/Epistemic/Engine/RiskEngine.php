<?php
declare(strict_types=1);

namespace Mixudev\SecurityDefense\Epistemic\Engine;

use Mixudev\SecurityDefense\Epistemic\Belief\ThreatBelief;
use Mixudev\SecurityDefense\Epistemic\Contracts\RiskEngineInterface;
use Mixudev\SecurityDefense\Epistemic\ValueObjects\RiskScore;

final class RiskEngine implements RiskEngineInterface
{
    public function __construct(private readonly float $decay = 0.95, private readonly float $epsilon = 0.001, private readonly int $maxIterations = 10) {}

    public function calculate(ThreatBelief $belief, RiskScore $current, array $config = []): RiskScore
    {
        $decay = (float) ($config['decay'] ?? $this->decay);
        $epsilon = (float) ($config['epsilon'] ?? $this->epsilon);
        $maxIterations = (int) ($config['max_iterations'] ?? $this->maxIterations);
        $sCount = count($belief->supportingEvidence); $cCount = count($belief->contradictingEvidence); $total = $sCount + $cCount;
        $signal = $total > 0 ? $sCount / $total : 0.0;
        $damper = $total > 0 ? ($cCount / $total) * 0.1 : 0.0;
        $risk = $current->toFloat(); $best = $risk;
        for ($i = 0; $i < $maxIterations; $i++) {
            $next = $risk + (1.0 - $risk) * $belief->confidence->toFloat() * $signal * $decay - $damper;
            $next = max(0.0, min(1.0, $next)); $best = $next;
            if (abs($next - $risk) < $epsilon) break;
            $risk = $next;
        }
        return RiskScore::from($best);
    }
}
