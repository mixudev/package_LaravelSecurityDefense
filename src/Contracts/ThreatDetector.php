<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Contracts;

use Mixudev\SecurityDefense\DTO\SecurityEvent;
use Mixudev\SecurityDefense\DTO\SecurityThreat;

/**
 * Contract for the primary anomaly detection engine.
 */
interface ThreatDetector
{
    /**
     * Analyze a security event across all registered and enabled detection rules.
     *
     * @param SecurityEvent $event
     * @return array<SecurityThreat> Detected threats (empty if no anomalies detected)
     */
    public function analyze(SecurityEvent $event): array;

    /**
     * Register a new detection rule dynamically.
     */
    public function registerRule(DetectionRule $rule): self;

    /**
     * Retrieve all registered detection rules.
     *
     * @return array<DetectionRule>
     */
    public function getRules(): array;
}
