<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;
use Mixudev\SecurityDefense\DTO\SecurityEvent;
use Mixudev\SecurityDefense\DTO\SecurityThreat;

/**
 * Event dispatched immediately when a detection rule flags an anomaly.
 */
class ThreatDetected
{
    use Dispatchable, SerializesModels;

    /**
     * @param SecurityThreat $threat
     * @param SecurityEvent $originEvent
     */
    public function __construct(
        public readonly SecurityThreat $threat,
        public readonly SecurityEvent $originEvent
    ) {
    }
}
