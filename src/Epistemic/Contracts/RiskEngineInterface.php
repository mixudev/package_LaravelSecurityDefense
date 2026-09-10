<?php
declare(strict_types=1);

namespace Mixudev\SecurityDefense\Epistemic\Contracts;

use Mixudev\SecurityDefense\Epistemic\Belief\ThreatBelief;
use Mixudev\SecurityDefense\Epistemic\ValueObjects\RiskScore;

interface RiskEngineInterface
{
    /** @param array<string, mixed> $config */
    public function calculate(ThreatBelief $belief, RiskScore $current, array $config): RiskScore;
}
