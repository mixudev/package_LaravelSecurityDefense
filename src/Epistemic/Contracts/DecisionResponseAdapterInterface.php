<?php
declare(strict_types=1);

namespace Mixudev\SecurityDefense\Epistemic\Contracts;

use Mixudev\SecurityDefense\Epistemic\Policy\ThreatDecision;
use Mixudev\SecurityDefense\Epistemic\Response\ResponseResult;

interface DecisionResponseAdapterInterface
{
    public function respond(ThreatDecision $decision): ResponseResult;
}
