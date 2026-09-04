<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Services;

use Mixudev\SecurityDefense\Contracts\ThreatDetector;
use Mixudev\SecurityDefense\Contracts\ThreatSource;
use Mixudev\SecurityDefense\DTO\SecurityEvent;
use Mixudev\SecurityDefense\DTO\SecurityThreat;
use Mixudev\SecurityDefense\Models\SecurityAlert;
use Mixudev\SecurityDefense\Sources\GenericArraySource;

/**
 * Main coordinator service managing detection, persistence, and alerting.
 */
class SecurityDefenseManager
{
    public function __construct(
        protected ThreatDetector $detector,
        protected AlertDispatcher $dispatcher
    ) {
    }

    /**
     * Record a security telemetry source, analyze anomalies, and dispatch alerts.
     *
     * @param ThreatSource|array<string, mixed> $source
     * @return array<SecurityThreat>
     */
    public function record(ThreatSource|array $source): array
    {
        $event = $source instanceof ThreatSource
            ? $source->toSecurityEvent()
            : (new GenericArraySource($source))->toSecurityEvent();

        return $this->processEvent($event);
    }

    /**
     * Process a normalized SecurityEvent through the detection engine and alert dispatcher.
     *
     * @param SecurityEvent $event
     * @return array<SecurityThreat>
     */
    public function processEvent(SecurityEvent $event): array
    {
        $threats = $this->detector->analyze($event);

        foreach ($threats as $threat) {
            $this->dispatcher->dispatch($threat);
        }

        return $threats;
    }

    /**
     * Resolve an alert by ID or instance.
     */
    public function resolveAlert(int|SecurityAlert $alert): bool
    {
        $model = is_int($alert) ? SecurityAlert::query()->findOrFail($alert) : $alert;

        return $this->dispatcher->resolveAlert($model);
    }

    /**
     * Get the underlying anomaly detection engine.
     */
    public function detector(): ThreatDetector
    {
        return $this->detector;
    }

    /**
     * Get the underlying alert dispatcher.
     */
    public function dispatcher(): AlertDispatcher
    {
        return $this->dispatcher;
    }
}
