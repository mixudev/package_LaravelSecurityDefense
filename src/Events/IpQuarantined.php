<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

/**
 * Event fired when an IP address is placed into quarantine.
 */
class IpQuarantined
{
    use Dispatchable, SerializesModels;

    /**
     * @param string $ip
     * @param int $duration
     * @param string $reason
     */
    public function __construct(
        public readonly string $ip,
        public readonly int $duration,
        public readonly string $reason
    ) {
    }
}
