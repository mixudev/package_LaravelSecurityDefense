<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Contracts;

use Mixudev\SecurityDefense\DTO\SecurityEvent;

/**
 * Contract for normalizing raw security events into standard SecurityEvent DTO.
 */
interface ThreatSource
{
    /**
     * Convert source telemetry into a normalized SecurityEvent.
     */
    public function toSecurityEvent(): SecurityEvent;
}
