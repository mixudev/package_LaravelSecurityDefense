<?php
declare(strict_types=1);

namespace Mixudev\SecurityDefense\Epistemic\Response;

use Mixudev\SecurityDefense\Epistemic\Contracts\DecisionResponseAdapterInterface;
use Mixudev\SecurityDefense\Epistemic\Policy\ThreatDecision;

/**
 * Default no-op adapter: never enforces a decision. Returns an auditable
 * ResponseResult so callers can observe that a decision was assessed without
 * any side effect. Host applications must provide and explicitly opt in to a
 * real adapter via `epistemic.response.adapter` before any enforcement occurs.
 */
final class NoopResponseAdapter implements DecisionResponseAdapterInterface
{
    public function respond(ThreatDecision $decision): ResponseResult
    {
        return ResponseResult::ignored($decision->id());
    }
}
