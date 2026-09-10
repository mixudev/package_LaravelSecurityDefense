<?php
declare(strict_types=1);

namespace Mixudev\SecurityDefense\Epistemic\Engine;

use Mixudev\SecurityDefense\Epistemic\Belief\ThreatBelief;
use Mixudev\SecurityDefense\Epistemic\Contracts\RiskEngineInterface;
use Mixudev\SecurityDefense\Epistemic\ValueObjects\RiskScore;

final class RiskEngine implements RiskEngineInterface
{
    private readonly float $decay;
    private readonly float $epsilon;
    private readonly int $maxIterations;

    public function __construct(float $decay = 0.95, float $epsilon = 0.001, int $maxIterations = 10)
    {
        if (!is_finite($decay) || $decay < 0.0 || $decay > 1.0) throw new \InvalidArgumentException('Risk decay must be finite and within [0, 1].');
        if (!is_finite($epsilon) || $epsilon <= 0.0) throw new \InvalidArgumentException('Risk epsilon must be finite and positive.');
        if ($maxIterations < 0 || $maxIterations > 10000) throw new \InvalidArgumentException('Risk max_iterations must be within [0, 10000].');
        $this->decay = $decay; $this->epsilon = $epsilon; $this->maxIterations = $maxIterations;
    }

    public function calculate(ThreatBelief $belief, RiskScore $current, array $config = []): RiskScore
    {
        $decay = (float) ($config['decay'] ?? $this->decay);
        $epsilon = (float) ($config['epsilon'] ?? $this->epsilon);
        $maxIterations = (int) ($config['max_iterations'] ?? $this->maxIterations);
        if (!is_finite($decay) || $decay < 0.0 || $decay > 1.0) throw new \InvalidArgumentException('Risk decay must be finite and within [0, 1].');
        if (!is_finite($epsilon) || $epsilon <= 0.0) throw new \InvalidArgumentException('Risk epsilon must be finite and positive.');
        if ($maxIterations < 0 || $maxIterations > 10000) throw new \InvalidArgumentException('Risk max_iterations must be within [0, 10000].');
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
