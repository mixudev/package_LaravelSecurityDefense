<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;
use Mixudev\SecurityDefense\Models\SecurityAlert;

/**
 * Event dispatched when an alert is resolved.
 */
class SecurityAlertResolved
{
    use Dispatchable, SerializesModels;

    /**
     * @param SecurityAlert $alert
     */
    public function __construct(
        public readonly SecurityAlert $alert
    ) {
    }
}
