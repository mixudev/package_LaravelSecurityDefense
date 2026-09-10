<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Services;

use Mixudev\SecurityDefense\Contracts\ThreatDetector;
use Mixudev\SecurityDefense\Contracts\ThreatSource;
use Mixudev\SecurityDefense\DTO\SecurityEvent;
use Mixudev\SecurityDefense\DTO\SecurityThreat;
use Mixudev\SecurityDefense\Epistemic\DTO\AnalysisContext;
use Mixudev\SecurityDefense\Epistemic\DTO\ThreatAssessment;
use Mixudev\SecurityDefense\Epistemic\EpistemicAnalyzer;
use Mixudev\SecurityDefense\Models\SecurityAlert;
use Mixudev\SecurityDefense\Sources\GenericArraySource;

/**
 * Enterprise coordinator service managing detection, threat scoring, persistence, and alerting.
 */
class SecurityDefenseManager
{
    public function __construct(
        protected ThreatDetector $detector,
        protected AlertDispatcher $dispatcher,
        protected ?ThreatScoringEngine $scoringEngine = null,
        protected ?IpQuarantineService $quarantineService = null,
        protected ?EpistemicAnalyzer $epistemicAnalyzer = null
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
     * Process a normalized SecurityEvent through detection engine, threat scoring, and alert dispatcher.
     *
     * @param SecurityEvent $event
     * @return array<SecurityThreat>
     */
    public function processEvent(SecurityEvent $event): array
    {
        $threats = $this->detector->analyze($event);

        foreach ($threats as $threat) {
            $this->dispatcher->dispatch($threat);

            // Feed threat into compound scoring engine
            if ($this->scoringEngine !== null && $this->scoringEngine->isEnabled()) {
                $compoundThreat = $this->scoringEngine->recordThreat($threat);
                if ($compoundThreat !== null) {
                    $threats[] = $compoundThreat;
                    $this->dispatcher->dispatch($compoundThreat);

                    // Auto-jail IP on compound critical threat
                    if ($this->quarantineService !== null && $event->ip !== '') {
                        $this->quarantineService->jail($event->ip, null, 'Auto-quarantined due to compound critical threat score');
                    }
                }
            }
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

    /**
     * Get the threat scoring engine.
     */
    public function scoring(): ?ThreatScoringEngine
    {
        return $this->scoringEngine;
    }

    /**
     * Get the IP quarantine service.
     */
    public function quarantine(): ?IpQuarantineService
    {
        return $this->quarantineService;
    }

    /**
     * Epistemic analysis: probabilistic, evidence-correlated threat assessment.
     * Opt-in. Does NOT replace record()/processEvent() — purely additive.
     *
     * @param AnalysisContext|array<SecurityEvent>|array<array<string, mixed>> $context
     */
    public function analyze(AnalysisContext|array $context): ThreatAssessment
    {
        if (!($context instanceof AnalysisContext)) {
            $events = array_map(
                fn($e) => $e instanceof SecurityEvent ? $e : SecurityEvent::fromArray((array) $e),
                $context
            );
            $context = new AnalysisContext(events: $events);
        }

        if ($this->epistemicAnalyzer === null) {
            throw new \RuntimeException(
                'EpistemicAnalyzer not available. Set epistemic.enabled = true in config/security-defense.php.'
            );
        }

        return $this->epistemicAnalyzer->analyze($context);
    }

    /**
     * Get the epistemic analyzer instance.
     */
    public function epistemic(): ?EpistemicAnalyzer
    {
        return $this->epistemicAnalyzer;
    }
}
