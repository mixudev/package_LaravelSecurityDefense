<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Contracts;

use Mixudev\SecurityDefense\DTO\SecurityEvent;
use Mixudev\SecurityDefense\DTO\SecurityThreat;

/**
 * Contract for extensible security anomaly detection rules.
 */
interface DetectionRule
{
    /**
     * Unique machine identifier of the rule (e.g., 'brute_force', 'credential_stuffing').
     */
    public function identifier(): string;

    /**
     * Human-readable name of the rule.
     */
    public function name(): string;

    /**
     * Whether the rule is currently active based on package configuration.
     */
    public function isEnabled(): bool;

    /**
     * Evaluate a normalized security event against the rule logic.
     *
     * @param SecurityEvent $event
     * @return SecurityThreat|null Returns SecurityThreat if anomaly is detected, null otherwise.
     */
    public function evaluate(SecurityEvent $event): ?SecurityThreat;
}
