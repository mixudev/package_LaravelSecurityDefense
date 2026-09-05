<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Services;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Mixudev\SecurityDefense\DTO\SecurityEvent;
use Mixudev\SecurityDefense\DTO\SecurityThreat;
use Mixudev\SecurityDefense\Support\Sanitizer;

/**
 * Records WAF threat telemetry: builds the SecurityThreat DTO, logs the block,
 * persists the alert via the dispatcher, and feeds the event into the
 * detection engine for full rule evaluation (compound scoring).
 */
class ThreatTelemetryRecorder
{
    public function __construct(
        protected SecurityDefenseManager $defenseManager
    ) {
    }

    /**
     * Process detected threat telemetry, record alert, and emit events.
     */
    public function handleDetectedAnomaly(
        Request $request,
        string $category,
        string $sample,
        string $field,
        string $severity = 'high'
    ): SecurityThreat {
        $ip = (string) ($request->ip() ?: '127.0.0.1');
        $identifier = $request->user()?->getAuthIdentifier() ?: ($request->input('email') ?: 'guest');

        $fingerprint = hash('sha256', sprintf('request_threat:%s:%s:%s', $category, $ip, $sample));

        $metadata = [
            'category' => $category,
            'matched_field' => $field,
            'matched_sample' => $sample,
            'method' => $request->method(),
            'path' => $request->path(),
            'url' => $request->fullUrl(),
            'ip' => $ip,
            'user_agent' => (string) ($request->userAgent() ?: ''),
        ];

        Log::warning(sprintf('SecurityDefense: Preventive WAF blocked %s attempt.', strtoupper($category)), [
            'ip' => $ip,
            'field' => $field,
            'path' => $request->path(),
            'category' => $category,
            'metadata' => Sanitizer::clean($metadata),
        ]);

        $threat = new SecurityThreat(
            severity: $severity,
            threatType: 'payload_injection',
            fingerprint: $fingerprint,
            metadata: $metadata,
            ruleIdentifier: 'request_threat_scanner'
        );

        $event = new SecurityEvent(
            ip: $ip,
            identifier: (string) $identifier,
            eventType: 'RequestThreatBlocked',
            timestamp: now()->toIso8601String(),
            userAgent: (string) ($request->userAgent() ?: ''),
            metadata: $metadata
        );

        // Persist the block alert AND wire SecurityEvent into detection engine for full rule evaluation
        $this->defenseManager->dispatcher()->dispatch($threat);
        $this->defenseManager->processEvent($event);

        return $threat;
    }
}