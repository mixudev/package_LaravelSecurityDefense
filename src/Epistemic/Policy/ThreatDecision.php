<?php
declare(strict_types=1);

namespace Mixudev\SecurityDefense\Epistemic\Policy;

final class ThreatDecision
{
    public function __construct(public readonly DecisionAction $action, public readonly string $reason, public readonly array $context = []) {}

    public function id(): string
    {
        return hash('sha256', $this->action->value . ':' . $this->reason . ':' . serialize($this->context));
    }
}
