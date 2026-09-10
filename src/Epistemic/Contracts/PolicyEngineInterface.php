<?php
declare(strict_types=1);

namespace Mixudev\SecurityDefense\Epistemic\Contracts;

use Mixudev\SecurityDefense\Epistemic\DTO\ThreatAssessment;
use Mixudev\SecurityDefense\Epistemic\Policy\ThreatDecision;

interface PolicyEngineInterface
{
    public function decide(ThreatAssessment $assessment): ThreatDecision;
}
