<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Middleware;

use Closure;
use Illuminate\Http\Request;
use Mixudev\SecurityDefense\DTO\SecurityEvent;
use Mixudev\SecurityDefense\DTO\SecurityThreat;
use Mixudev\SecurityDefense\Rules\PathReconnaissanceRule;
use Mixudev\SecurityDefense\Rules\PayloadInjectionRule;
use Mixudev\SecurityDefense\Rules\UserAgentAnomalyRule;
use Mixudev\SecurityDefense\Services\IpQuarantineService;
use Mixudev\SecurityDefense\Services\PayloadDecoder;
use Mixudev\SecurityDefense\Services\RequestFloodLimiter;
use Mixudev\SecurityDefense\Services\SecurityDefenseManager;
use Mixudev\SecurityDefense\Services\ThreatTelemetryRecorder;
use Mixudev\SecurityDefense\Support\ThreatResponseBuilder;

/**
 * Enterprise preventive WAF middleware with active IP quarantine and payload scanning.
 */
class RequestThreatScanner
{
    public function __construct(
        protected SecurityDefenseManager $defenseManager,
        protected PayloadInjectionRule $payloadRule,
        protected IpQuarantineService $quarantineService,
        protected PathReconnaissanceRule $reconRule,
        protected UserAgentAnomalyRule $uaRule,
        protected RequestFloodLimiter $floodLimiter,
        protected PayloadDecoder $payloadDecoder,
        protected ThreatResponseBuilder $responseBuilder,
        protected ThreatTelemetryRecorder $telemetryRecorder
    ) {
    }

    /**
     * Handle incoming request and inspect payloads.
     *
     * @param Request $request
     * @param Closure(Request): mixed $next
     * @return mixed
     */
    public function handle(Request $request, Closure $next): mixed
    {
        if (!$this->isEnabled()) {
            return $next($request);
        }

        $ip = (string) ($request->ip() ?: '127.0.0.1');

        // 0. Unconditional block of TRACE/TRACK (reflective-XSS vector, no legitimate use)
        $method = strtoupper((string) $request->method());
        if (in_array($method, ['TRACE', 'TRACK'], true)) {
            return $this->responseBuilder->buildBlockedResponse($request, new SecurityThreat(
                severity: 'high',
                threatType: 'http_method_abuse',
                fingerprint: hash('sha256', 'http_method_abuse:' . $method . ':' . $ip),
                metadata: ['category' => 'http_method_abuse', 'method' => $method, 'ip' => $ip],
                ruleIdentifier: 'request_threat_scanner'
            ));
        }

        // 1. Instant IP Quarantine Check (Zero CPU Overhead during active attack)
        if ($this->quarantineService->isQuarantined($ip)) {
            return $this->responseBuilder->buildQuarantinedResponse($request, $ip);
        }

        // 1b. Per-IP request flood limiter (cheap O(1) DoS/scraper guard)
        if ($this->floodLimiter->isExceeded($ip)) {
            return $this->responseBuilder->buildQuarantinedResponse($request, $ip);
        }

        if ($this->isExcluded($request)) {
            return $next($request);
        }

        // 2. User-Agent Anomaly Detection (scanners + empty UA when configured)
        $userAgent = (string) ($request->userAgent() ?: '');
        if ($this->uaRule->isEnabled() && (bool) config('security-defense.detection.rules.user_agent_anomaly.block_known_scanners', true)) {
            $uaEvent = new SecurityEvent(
                ip: $ip,
                identifier: $request->user()?->getAuthIdentifier() ?: ($request->input('email') ?: 'guest'),
                eventType: 'HttpRequestTelemetry',
                userAgent: $userAgent,
                metadata: ['path' => $request->path()]
            );
            $uaThreat = $this->uaRule->evaluate($uaEvent);
            if ($uaThreat !== null) {
                $threat = $this->telemetryRecorder->handleDetectedAnomaly(
                    $request,
                    'user_agent_anomaly',
                    $uaThreat->metadata['detected_tool'] ?? 'unknown',
                    'User-Agent',
                    'medium'
                );

                if (config('security-defense.middleware.payload_scanner.action', 'block') === 'block') {
                    return $this->responseBuilder->buildBlockedResponse($request, $threat);
                }
            }
        }

        // 3. Path Reconnaissance Probing Check
        $path = $request->path();
        if ($this->reconRule->isEnabled() && $this->reconRule->isSensitivePath($path)) {
            $threat = $this->telemetryRecorder->handleDetectedAnomaly(
                $request,
                'path_reconnaissance',
                $path,
                'path',
                'high'
            );

            if (config('security-defense.middleware.payload_scanner.action', 'block') === 'block') {
                return $this->responseBuilder->buildBlockedResponse($request, $threat);
            }
        }

        // 4. Payload Injection Inspection (Query, Path, Body)
        //    Fast-path: skip the regex scan entirely when there is no query string,
        //    no request body, and the path already passed the recon check. This keeps
        //    the cost of ordinary GET/HEAD traffic near-zero at scale (millions of req).
        $query = $request->query();
        $body = $this->hasRequestBody($request);
        $scanPayloads = !empty($query) || $body || $this->alwaysScanPayloads();

        if ($scanPayloads) {
            $inputsToScan = [
                'path' => $path,
                'query' => $query,
                'body' => $request->all(),
                'raw_content' => $request->getContent(),
            ];

            // Defense-in-depth: scan URL-decoded + CRLF-normalized copies to catch
            // Burp Suite / encoded payloads that bypass raw pattern matching.
            $inputsToScan = $this->payloadDecoder->addDecodedTargets($inputsToScan);

            $inspection = $this->payloadRule->inspect($inputsToScan);

            if ($inspection['matched']) {
                $threat = $this->telemetryRecorder->handleDetectedAnomaly(
                    $request,
                    (string) ($inspection['category'] ?? 'payload_injection'),
                    (string) ($inspection['sample'] ?? ''),
                    (string) ($inspection['field'] ?? 'unknown'),
                    'critical'
                );

                // Auto-jail malicious IP if enabled
                if ((bool) config('security-defense.middleware.quarantine.auto_jail_on_critical', true)) {
                    $this->quarantineService->jail($ip, null, 'Auto-quarantined due to payload injection attack: ' . ($inspection['category'] ?? ''));
                }

                if (config('security-defense.middleware.payload_scanner.action', 'block') === 'block') {
                    return $this->responseBuilder->buildBlockedResponse($request, $threat);
                }
            }
        }

        return $next($request);
    }

    protected function isEnabled(): bool
    {
        $global = (bool) config('security-defense.enabled', true);
        $middleware = (bool) config('security-defense.middleware.payload_scanner.enabled', true);

        return $global && $middleware;
    }

    protected function isExcluded(Request $request): bool
    {
        $excludedPaths = (array) config('security-defense.middleware.payload_scanner.excluded_paths', []);
        foreach ($excludedPaths as $pattern) {
            if ($request->is($pattern)) {
                return true;
            }
        }

        return false;
    }

    /**
         * Whether payload scanning should run even for empty/bodyless requests.
         */
        protected function alwaysScanPayloads(): bool
        {
            return (bool) config('security-defense.middleware.payload_scanner.scan_empty_requests', false);
        }

        /**
         * Cheap check whether the request carries any body content worth scanning.
         */
        protected function hasRequestBody(Request $request): bool
        {
            $content = $request->getContent();

            return is_string($content) && trim($content) !== '';
        }
    }
