<?php
declare(strict_types=1);

namespace Mixudev\SecurityDefense\Epistemic\Policy;

enum DecisionAction: string
{
    case ALLOW = 'allow'; case MONITOR = 'monitor'; case CHALLENGE = 'challenge'; case QUARANTINE = 'quarantine'; case BLOCK = 'block'; case NOTIFY = 'notify';
}
