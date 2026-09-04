<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Detection;

use Mixudev\SecurityDefense\Contracts\DetectionRule;
use Mixudev\SecurityDefense\Contracts\ThreatDetector;
use Mixudev\SecurityDefense\DTO\SecurityEvent;
use Mixudev\SecurityDefense\DTO\SecurityThreat;
use Mixudev\SecurityDefense\Events\ThreatDetected;

/**
 * Primary anomaly detection engine evaluating events against registered rules.
 */
class AnomalyDetector implements ThreatDetector
{
    /**
     * Registered detection rules.
     *
     * @var array<string, DetectionRule>
     */
    protected array $rules = [];

    /**
     * @param iterable<DetectionRule> $rules
     */
    public function __construct(iterable $rules = [])
    {
        foreach ($rules as $rule) {
            $this->registerRule($rule);
        }
    }

    /**
     * Register a detection rule.
     */
    public function registerRule(DetectionRule $rule): self
    {
        $this->rules[$rule->identifier()] = $rule;

        return $this;
    }

    /**
     * Retrieve all registered rules.
     *
     * @return array<string, DetectionRule>
     */
    public function getRules(): array
    {
        return $this->rules;
    }

    /**
     * Analyze a security event across all registered and active rules.
     *
     * @param SecurityEvent $event
     * @return array<SecurityThreat>
     */
    public function analyze(SecurityEvent $event): array
    {
        if (!(bool) config('security-defense.enabled', true)) {
            return [];
        }

        if (!(bool) config('security-defense.detection.enabled', true)) {
            return [];
        }

        $detectedThreats = [];

        foreach ($this->rules as $rule) {
            if (!$rule->isEnabled()) {
                continue;
            }

            $threat = $rule->evaluate($event);

            if ($threat !== null) {
                $detectedThreats[] = $threat;

                // Dispatch domain event immediately for host application listeners
                event(new ThreatDetected($threat, $event));
            }
        }

        return $detectedThreats;
    }
}
