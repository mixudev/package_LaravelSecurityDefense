<?php
declare(strict_types=1);

namespace Mixudev\SecurityDefense\Epistemic\Engine;

use Mixudev\SecurityDefense\Epistemic\Contracts\EpistemicEngineInterface;
use Mixudev\SecurityDefense\Epistemic\ValueObjects\Confidence;

final class EpistemicEngine implements EpistemicEngineInterface
{
    public function __construct(
        private readonly float $supportingFactor = 0.3,
        private readonly float $contradictingFactor = 0.25,
        private readonly float $evidenceTtlSeconds = 900.0,
        private readonly float $confidenceMin = 0.0,
        private readonly float $confidenceMax = 1.0,
    ) {}

    public function computeConfidence(array $supporting, array $contradicting): Confidence
    {
        $c = 0.5;
        foreach ($supporting as $e) {
            $w = $e->reliability->toFloat() * $e->freshness((int) $this->evidenceTtlSeconds);
            $c += $w * (1.0 - $c) * $this->supportingFactor;
        }
        foreach ($contradicting as $e) {
            $w = $e->reliability->toFloat() * $e->freshness((int) $this->evidenceTtlSeconds);
            $c -= $w * $c * $this->contradictingFactor;
        }
        return Confidence::from(max($this->confidenceMin, min($this->confidenceMax, $c)));
    }
}
