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

        // 0. Unconditional block of TRACE/TRACK (reflective-XSS vector, no legitimate use)
        $method = strtoupper((string) $request->method());
        if (in_array($method, ['TRACE', 'TRACK'], true)) {
            return $this->buildBlockedResponse($request, new SecurityThreat(
                severity: 'high',
                threatType: 'http_method_abuse',
                fingerprint: hash('sha256', 'http_method_abuse:' . $method . ':' . $ip),
                metadata: ['category' => 'http_method_abuse', 'method' => $method, 'ip' => $ip],
                ruleIdentifier: 'request_threat_scanner'
            ));
        }

        // 1. Instant IP Quarantine Check (Zero CPU Overhead during active attack)
        if ($this->quarantineService->isQuarantined($ip)) {
            return $this->buildQuarantinedResponse($request, $ip);
        }

        // 1b. Per-IP request flood limiter (cheap O(1) DoS/scraper guard)
        if ($this->isRequestFloodExceeded($ip)) {
            return $this->buildQuarantinedResponse($request, $ip);
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
                $threat = $this->handleDetectedAnomaly(
                    $request,
                    'user_agent_anomaly',
                    $uaThreat->metadata['detected_tool'] ?? 'unknown',
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
            $inputsToScan = $this->addDecodedTargets($inputsToScan);

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
        }

        return $next($request);
    }

    /**
     * Process detected threat telemetry, record alert, and emit events.
     * Feeds SecurityEvent into detection engine for full rule evaluation.
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

        // Persist the block alert AND wire SecurityEvent into detection engine for full rule evaluation
        $this->defenseManager->dispatcher()->dispatch($threat);
        $this->defenseManager->processEvent($event);

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

    /**
     * Whether per-IP request flood limiting is enabled and this IP has exceeded
     * the windowed cap. Implemented as a cheap atomic cache increment (O(1))
     * so under a DDoS/scraper flood the expensive regex scans are never reached.
     */
    protected function isRequestFloodExceeded(string $ip): bool
    {
        $cfg = (array) config('security-defense.middleware.request_flood', []);
        if (empty($cfg['enabled'])) {
            return false;
        }

        $max = (int) ($cfg['max_requests_per_second'] ?? 200);
        $window = (int) ($cfg['window'] ?? 5);
        $targetJail = (int) ($cfg['jail_after_exceeding'] ?? 2);

        $prefix = (string) config('security-defense.cache_prefix', 'security_defense:');
        $key = sprintf('%sflood:%s:%d', $prefix, md5($ip), (int) floor(time() / $window));

        $cache = $this->getFloodCache();

        // Atomic increment; seeds TTL on first touch
        $count = (int) $cache->increment($key);
        if ($count === 1) {
            $cache->put($key, 1, $window);
        }

        if ($count <= $max) {
            return false;
        }

        // Exceeded: count consecutive windows; jail once past threshold
        $strikeKey = sprintf('%sflood:strike:%s', $prefix, md5($ip));
        $strikes = (int) $cache->increment($strikeKey);
        if ($strikes === 1) {
            $cache->put($strikeKey, 1, $window * 4);
        }
        if ($strikes >= $targetJail) {
            $this->quarantineService->jail($ip, null, 'Auto-quarantined: request flood exceeding ' . $max . ' req/s per IP');
        }

        // Always reject while over cap (fail-closed under active flood)
        return true;
    }

    /**
     * Cheap check whether the request carries any body content worth scanning.
     */
    protected function hasRequestBody(Request $request): bool
    {
        $content = $request->getContent();

        return is_string($content) && trim($content) !== '';
    }

    /**
     * Whether payload scanning should run even for empty/bodyless requests.
     */
    protected function alwaysScanPayloads(): bool
    {
        return (bool) config('security-defense.middleware.payload_scanner.scan_empty_requests', false);
    }

    /**
     * Cache repository used for flood counters (matches quarantine/scoring store).
     */
    protected function getFloodCache(): \Illuminate\Contracts\Cache\Repository
    {
        $store = config('security-defense.cache_store');

        return \Illuminate\Support\Facades\Cache::store($store);
    }

    /**
     * Add URL-decoded and CRLF-normalized copies of all string values so the
     * payload scanner can match against the semantic content even if the raw
     * request uses percent-encoding, double-encoding, or CRLF obfuscation.
     *
     * ponytail: per-field depth limit keeps cost linear; nested arrays use
     * Fluent::flatten(); add recursive walker when input trees exceed 10K nodes.
     */
    protected function addDecodedTargets(array $inputs): array
    {
        $decoded = [];
        $rawContent = $inputs['raw_content'] ?? '';
        if (is_string($rawContent) && $rawContent !== '') {
            $decoded['raw_decoded'] = rawurldecode($rawContent);
            // Normalize CRLF/CR/LF to spaces so CRLF injection shows as literal pattern
            $decoded['raw_crlf_normalized'] = str_replace(["\r\n", "\r", "\n"], ' ', $rawContent);
            // Unicode escape sequences (Burp Suite / JS obfuscation): \u0027 -> '
            $decoded['raw_unicode_decoded'] = preg_replace_callback('/\\\\u([0-9a-fA-F]{4})/i', static fn ($m) => mb_chr((int) hexdec($m[1]), 'UTF-8'), $rawContent);
        }

        foreach (['query', 'body'] as $source) {
            if (empty($inputs[$source]) || !is_array($inputs[$source])) {
                continue;
            }
            $flat = \Illuminate\Support\Arr::flatten($inputs[$source]);
            $parts = [];
            foreach ($flat as $value) {
                if (!is_string($value)) {
                    continue;
                }
                $parts[] = rawurldecode($value);
                // Double-decode for %2527 -> %27 -> ' (Burp double-encoding)
                $parts[] = rawurldecode(rawurldecode($value));
                $parts[] = str_replace(["\r\n", "\r", "\n"], ' ', $value);
                // Unicode escape sequences: \u0027 -> ' (Burp/JS obfuscation)
                $parts[] = preg_replace_callback('/\\\\u([0-9a-fA-F]{4})/i', static fn ($m) => mb_chr((int) hexdec($m[1]), 'UTF-8'), $value);
                // Fullwidth Unicode normalization: ＳＥＬＥＣＴ -> SELECT (NFKC) when intl available
                $normalizer = class_exists('\Normalizer') ? \Normalizer::normalize($value, \Normalizer::FORM_KC) : null;
                if ($normalizer !== false && $normalizer !== null && $normalizer !== $value) {
                    $parts[] = $normalizer;
                }
                // Literal escape-sequence decode: \s\s -> spaces, \t -> tab (sqlmap/etc.)
                $parts[] = str_replace(['\\s', '\\t', '\\n', '\\r'], [' ', "\t", "\n", "\r"], $value);
            }
            if (!empty($parts)) {
                $decoded[$source . '_decoded'] = implode(' ', $parts);
            }
        }

        return array_merge($inputs, $decoded);
    }
}
