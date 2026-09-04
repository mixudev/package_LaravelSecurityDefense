<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;
use Mixudev\SecurityDefense\DTO\SecurityThreat;
use Mixudev\SecurityDefense\Models\SecurityAlert;

/**
 * Event dispatched after an alert is persisted to the database and dispatched to channels.
 */
class SecurityAlertCreated
{
    use Dispatchable, SerializesModels;

    /**
     * @param SecurityAlert $alert
     * @param SecurityThreat $threat
     */
    public function __construct(
        public readonly SecurityAlert $alert,
        public readonly SecurityThreat $threat
    ) {
    }
}
