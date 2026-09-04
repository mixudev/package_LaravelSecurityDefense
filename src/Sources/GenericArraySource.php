<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Sources;

use Mixudev\SecurityDefense\Contracts\ThreatSource;
use Mixudev\SecurityDefense\DTO\SecurityEvent;

/**
 * Generic array adapter implementing ThreatSource.
 */
class GenericArraySource implements ThreatSource
{
    /**
     * @param array<string, mixed> $payload
     */
    public function __construct(protected array $payload)
    {
    }

    /**
     * Convert payload into normalized SecurityEvent DTO.
     */
    public function toSecurityEvent(): SecurityEvent
    {
        return SecurityEvent::fromArray($this->payload);
    }
}
