<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Middleware;

use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Log;
use Mixudev\SecurityDefense\DTO\SecurityEvent;
use Mixudev\SecurityDefense\DTO\SecurityThreat;
use Mixudev\SecurityDefense\Rules\PathReconnaissanceRule;
use Mixudev\SecurityDefense\Rules\PayloadInjectionRule;
use Mixudev\SecurityDefense\Rules\UserAgentAnomalyRule;
use Mixudev\SecurityDefense\Services\IpQuarantineService;
use Mixudev\SecurityDefense\Services\SecurityDefenseManager;
use Mixudev\SecurityDefense\Support\Sanitizer;

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
        protected UserAgentAnomalyRule $uaRule
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

        // 1. Instant IP Quarantine Check (Zero CPU Overhead during active attack)
        if ($this->quarantineService->isQuarantined($ip)) {
            return $this->buildQuarantinedResponse($request, $ip);
        }

        if ($this->isExcluded($request)) {
            return $next($request);
        }

        // 2. User-Agent Scanner Tool Check
        $userAgent = (string) ($request->userAgent() ?: '');
        if ($userAgent !== '' && $this->uaRule->isEnabled() && (bool) config('security-defense.detection.rules.user_agent_anomaly.block_known_scanners', true)) {
            $scannerTool = $this->uaRule->identifyScanner($userAgent);
            if ($scannerTool !== null) {
                $threat = $this->handleDetectedAnomaly(
                    $request,
                    'user_agent_anomaly',
                    sprintf('Known scanning tool: %s', $scannerTool),
                    'User-Agent',
                    'medium'
                );

                if (config('security-defense.middleware.payload_scanner.action', 'block') === 'block') {
                    return $this->buildBlockedResponse($request, $threat);
                }
            }
        }

        // 3. Path Reconnaissance Probing Check
        $path = $request->path();
        if ($this->reconRule->isEnabled() && $this->reconRule->isSensitivePath($path)) {
            $threat = $this->handleDetectedAnomaly(
                $request,
                'path_reconnaissance',
                $path,
                'path',
                'high'
            );

            if (config('security-defense.middleware.payload_scanner.action', 'block') === 'block') {
                return $this->buildBlockedResponse($request, $threat);
            }
        }

        // 4. Payload Injection Inspection (Query, Path, Body)
        $inputsToScan = [
            'path' => $path,
            'query' => $request->query(),
            'body' => $request->all(),
        ];

        $inspection = $this->payloadRule->inspect($inputsToScan);

        if ($inspection['matched']) {
            $threat = $this->handleDetectedAnomaly(
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
                return $this->buildBlockedResponse($request, $threat);
            }
        }

        return $next($request);
    }

    /**
     * Process detected threat telemetry, record alert, and emit events.
     */
    protected function handleDetectedAnomaly(
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

        $this->defenseManager->dispatcher()->dispatch($threat);

        return $threat;
    }

    /**
     * Build response for quarantined IP.
     */
    protected function buildQuarantinedResponse(Request $request, string $ip): Response|JsonResponse
    {
        $status = (int) config('security-defense.middleware.quarantine.response_status', 429);
        $message = (string) config(
            'security-defense.middleware.quarantine.response_message',
            'Your IP has been temporarily quarantined due to suspicious security activity.'
        );

        if ($request->expectsJson() || $request->is('api/*')) {
            return response()->json([
                'error' => 'Quarantined',
                'message' => $message,
                'ip' => $ip,
            ], $status);
        }

        return response(
            sprintf(
                '<!DOCTYPE html><html><head><title>429 Quarantined</title></head><body style="font-family:sans-serif;text-align:center;padding:50px;"><h1>Access Quarantined</h1><p>%s</p><small>IP: %s</small></body></html>',
                htmlspecialchars($message, ENT_QUOTES, 'UTF-8'),
                htmlspecialchars($ip, ENT_QUOTES, 'UTF-8')
            ),
            $status,
            ['Content-Type' => 'text/html; charset=UTF-8']
        );
    }

    /**
     * Build appropriate blocked HTTP response.
     */
    protected function buildBlockedResponse(Request $request, SecurityThreat $threat): Response|JsonResponse
    {
        $status = (int) config('security-defense.middleware.payload_scanner.response_status', 403);
        $message = (string) config(
            'security-defense.middleware.payload_scanner.response_message',
            'Suspicious request payload detected and blocked.'
        );

        if ($request->expectsJson() || $request->is('api/*')) {
            return response()->json([
                'error' => 'Forbidden',
                'message' => $message,
                'threat_id' => substr($threat->fingerprint, 0, 16),
            ], $status);
        }

        return response(
            sprintf(
                '<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body style="font-family:sans-serif;text-align:center;padding:50px;"><h1>403 Forbidden</h1><p>%s</p><small>Reference ID: %s</small></body></html>',
                htmlspecialchars($message, ENT_QUOTES, 'UTF-8'),
                htmlspecialchars(substr($threat->fingerprint, 0, 16), ENT_QUOTES, 'UTF-8')
            ),
            $status,
            ['Content-Type' => 'text/html; charset=UTF-8']
        );
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
}
