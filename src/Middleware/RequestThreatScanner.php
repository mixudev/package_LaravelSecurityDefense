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
use Mixudev\SecurityDefense\Rules\PayloadInjectionRule;
use Mixudev\SecurityDefense\Services\SecurityDefenseManager;
use Mixudev\SecurityDefense\Support\Sanitizer;

/**
 * Preventive WAF middleware inspecting inbound HTTP request payloads before reaching handlers.
 */
class RequestThreatScanner
{
    public function __construct(
        protected SecurityDefenseManager $defenseManager,
        protected PayloadInjectionRule $payloadRule
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

        if ($this->isExcluded($request)) {
            return $next($request);
        }

        // Collect inputs to scan: query params, body inputs, and URI path
        $inputsToScan = [
            'path' => $request->path(),
            'query' => $request->query(),
            'body' => $request->all(),
        ];

        $inspection = $this->payloadRule->inspect($inputsToScan);

        if ($inspection['matched']) {
            $threat = $this->handleDetectedThreat($request, $inspection);

            $action = config('security-defense.middleware.payload_scanner.action', 'block');

            if ($action === 'block') {
                return $this->buildBlockedResponse($request, $threat);
            }
        }

        return $next($request);
    }

    /**
     * Process detected threat telemetry, record alert, and emit events.
     *
     * @param Request $request
     * @param array{matched: bool, category: string|null, sample: string|null, field: string|null} $inspection
     * @return SecurityThreat
     */
    protected function handleDetectedThreat(Request $request, array $inspection): SecurityThreat
    {
        $category = (string) ($inspection['category'] ?? 'payload_injection');
        $sample = (string) ($inspection['sample'] ?? '');
        $field = (string) ($inspection['field'] ?? 'unknown');

        $ip = (string) ($request->ip() ?: '127.0.0.1');
        $identifier = $request->user()?->getAuthIdentifier() ?: ($request->input('email') ?: 'guest');

        $fingerprint = hash('sha256', sprintf('payload_injection:%s:%s:%s', $category, $ip, $sample));

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

        // Safe logging without leaking unredacted secrets
        Log::warning(sprintf('SecurityDefense: Preventive WAF blocked %s attempt.', strtoupper($category)), [
            'ip' => $ip,
            'field' => $field,
            'path' => $request->path(),
            'category' => $category,
            'metadata' => Sanitizer::clean($metadata),
        ]);

        $threat = new SecurityThreat(
            severity: 'critical',
            threatType: 'payload_injection',
            fingerprint: $fingerprint,
            metadata: $metadata,
            ruleIdentifier: 'payload_injection'
        );

        $event = new SecurityEvent(
            ip: $ip,
            identifier: (string) $identifier,
            eventType: 'RequestThreatBlocked',
            timestamp: now()->toIso8601String(),
            userAgent: (string) ($request->userAgent() ?: ''),
            metadata: $metadata
        );

        // Record via manager (dispatches ThreatDetected, alert persistence, dedupe, channels)
        $this->defenseManager->dispatcher()->dispatch($threat);

        return $threat;
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

    /**
     * Determine if scanner middleware is enabled.
     */
    protected function isEnabled(): bool
    {
        $global = (bool) config('security-defense.enabled', true);
        $middleware = (bool) config('security-defense.middleware.payload_scanner.enabled', true);

        return $global && $middleware;
    }

    /**
     * Check whether current path is excluded from scanning.
     */
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
