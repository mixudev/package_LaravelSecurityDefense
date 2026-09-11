<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Http\Controllers;

use DateTimeImmutable;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\RateLimiter;
use Mixudev\SecurityDefense\Epistemic\Belief\ThreatBelief;
use Mixudev\SecurityDefense\Epistemic\Belief\ThreatHypothesis;
use Mixudev\SecurityDefense\Epistemic\ValueObjects\Confidence;
use Mixudev\SecurityDefense\Epistemic\Evidence\Evidence;
use Mixudev\SecurityDefense\Support\Facades\SecurityDefense;
use Mixudev\SecurityDefense\Models\SecurityAlert;
use Mixudev\SecurityDefense\Services\ChannelTestService;
use Mixudev\SecurityDefense\Services\ConfigWriterService;
use Mixudev\SecurityDefense\Services\DashboardAnalyticsService;
use Mixudev\SecurityDefense\Services\DataAuditQueryService;
use Mixudev\SecurityDefense\Services\IpQuarantineService;
use Mixudev\SecurityDefense\Services\SessionIntelligenceQueryService;
use Mixudev\SecurityDefense\Support\DateRangeFilter;
use Throwable;

/**
 * Enterprise Monitoring Dashboard controller.
 * Restricted strictly to authorized environments and authenticated security personnel.
 */
class DashboardController extends Controller
{
    public function __construct(
        protected DashboardAnalyticsService $analyticsService,
        protected ChannelTestService $channelTestService,
        protected IpQuarantineService $quarantineService,
        protected DataAuditQueryService $auditQueryService,
        protected SessionIntelligenceQueryService $sessionQueryService,
    ) {
    }

    /**
     * Display the Security Defense monitoring dashboard.
     */
    public function index(Request $request, ?ChannelTestService $testService = null)
    {
        $refresh = $request->boolean('refresh');
        if ($refresh) {
            $this->analyticsService->clearCache();
        }

        $stats = $this->analyticsService->getStats($refresh);
        $hourlyData = $this->analyticsService->getHourlyTimeline($refresh);
        $threatDistribution = $this->analyticsService->getThreatDistribution($refresh);
        $quarantinedIps = $this->analyticsService->getActiveQuarantines($refresh);
        $channelsStatus = ($testService ?? $this->channelTestService)->getChannelsStatus();
        $postureScore = $this->analyticsService->calculatePostureScore($stats);
        $lastAnalysis = Cache::store(config('security-defense.cache_store'))->get(
            (string) config('security-defense.cache_prefix', 'security_defense:') . 'epistemic:last_analysis'
        );
        $epistemicSummary = [
            'enabled' => (bool) config('security-defense.epistemic.enabled', false),
            'patterns' => $this->epistemicFeedbackCount(),
            'risk' => is_array($lastAnalysis) && is_numeric($lastAnalysis['risk'] ?? null) ? (float) $lastAnalysis['risk'] : null,
        ];

        $filters = $request->only(['status', 'severity', 'threat_type', 'range']);
        $dateRange = DateRangeFilter::resolve($request);
        $filters['from'] = $dateRange['from'];
        $filters['to'] = $dateRange['to'];
        $alerts = $this->analyticsService->getFilteredAlerts($filters, 15);
        $liveEvents = $this->analyticsService->getLiveBlockedEvents(10);

        return view('security-defense::dashboard', [
            'stats' => $stats,
            'epistemicSummary' => $epistemicSummary,
            'alerts' => $alerts,
            'liveEvents' => $liveEvents,
            'dateRange' => $dateRange,
            'quickActions' => [
                'blockHeadless' => (bool) config('security-defense.middleware.user_agent_anomaly.block_headless_clients', false),
                'cspArmor' => (bool) config('security-defense.csp_armor.enabled', true),
                'asyncQueue' => (bool) config('security-defense.data_audit.queue.enabled', false),
            ],
            'hourlyData' => $hourlyData,
            'postureScore' => $postureScore,
            'threatDistribution' => $threatDistribution,
            'quarantinedIps' => $quarantinedIps,
            'channelsStatus' => $channelsStatus,
            'filters' => $filters,
        ]);
    }

    /**
     * Display epistemic analysis telemetry.
     */
    public function epistemic()
    {
        $recent = SecurityAlert::query()->latest()->limit(100)->get(['metadata']);
        $scores = $recent->map(fn (SecurityAlert $alert) => $this->epistemicScores($alert->metadata))->filter();
        $lastAnalysis = Cache::store(config('security-defense.cache_store'))->get(
            (string) config('security-defense.cache_prefix', 'security_defense:') . 'epistemic:last_analysis'
        );

        $analysis = is_array($lastAnalysis) ? $lastAnalysis : [];
        $hypotheses = $this->normaliseHypotheses($analysis['hypotheses'] ?? []);
        $evidenceFeed = $this->normaliseEvidence($analysis['evidence_feed'] ?? []);
        $memoryPatterns = $this->epistemicFeedbackCount();

        return view('security-defense::epistemic', [
            'stats' => [
                'total_analyses' => $recent->count(),
                'average_risk' => round((float) ($scores->avg('risk') ?? 0), 3),
                'average_confidence' => round((float) ($scores->avg('confidence') ?? 0), 3),
                'feedback_count' => $memoryPatterns,
                'memory_patterns' => $memoryPatterns,
            ],
            'hypotheses' => $hypotheses,
            'evidenceFeed' => $evidenceFeed,
            'responseAdapters' => [$this->epistemicAdapterStatus()],
            'feedbackRoute' => route('security-defense.epistemic.feedback'),
            'epistemicConfig' => (array) config('security-defense.epistemic', []),
        ]);
    }

    /**
     * Record verified epistemic feedback.
     */
    public function epistemicFeedback(Request $request): RedirectResponse
    {
        $request->validate([
            'hypothesis' => 'required|string|in:account_compromise,credential_stuffing,session_hijack,brute_force_attack,data_exfiltration,insider_threat,automated_scraping,impossible_travel,payload_attack,bot_activity,compound_attack,unknown',
            'outcome' => 'required|string|in:confirmed_attack,false_positive',
        ]);

        if ((bool) config('security-defense.epistemic.enabled', false)) {
            $hypothesis = ThreatHypothesis::from((string) $request->input('hypothesis'));
            SecurityDefense::recordFeedback(
                new ThreatBelief($hypothesis, Confidence::from(0.5), [], [], new DateTimeImmutable()),
                (string) $request->input('outcome')
            );
        }

        return back()->with('status_message', 'Epistemic feedback recorded.');
    }

    /** @return array{risk: float, confidence: float}|null */
    private function epistemicScores(?array $metadata): ?array
    {
        if (!is_array($metadata)) return null;
        $risk = $metadata['risk'] ?? $metadata['epistemic']['risk'] ?? null;
        $confidence = $metadata['confidence'] ?? $metadata['epistemic']['confidence'] ?? null;
        return is_numeric($risk) && is_numeric($confidence) ? ['risk' => (float) $risk, 'confidence' => (float) $confidence] : null;
    }

    /** @return array{class: string, enabled: bool, last_response: string} */
    private function epistemicAdapterStatus(): array
    {
        $cfg = (array) config('security-defense.epistemic.response', []);
        $adapter = is_string($cfg['adapter'] ?? null) ? (string) $cfg['adapter'] : 'NoopResponseAdapter';

        return [
            'class' => $adapter,
            'enabled' => (bool) ($cfg['enabled'] ?? false) && $adapter !== 'NoopResponseAdapter',
            'last_response' => 'No response recorded',
        ];
    }

    private function epistemicFeedbackCount(): int
    {
        $index = Cache::get((string) config('security-defense.cache_prefix', 'security_defense:') . 'ep:pattern-index', []);
        return is_array($index) ? count($index) : 0;
    }

    /**
     * @param  array<int, array<string, mixed>|ThreatBelief> $raw
     * @return list<array{hypothesis: string, confidence: float, risk: float, supporting: array<int, string>, contradicting: array<int, string>, action: string}>
     */
    private function normaliseHypotheses(array $raw): array
    {
        $out = [];
        foreach ($raw as $belief) {
            if ($belief instanceof ThreatBelief) {
                $out[] = [
                    'hypothesis' => $belief->hypothesis->value,
                    'confidence' => $belief->confidence->toFloat(),
                    'risk' => 0.0,
                    'supporting' => array_map(fn($e) => $e->type->value, $belief->supportingEvidence),
                    'contradicting' => array_map(fn($e) => $e->type->value, $belief->contradictingEvidence),
                    'action' => 'monitor',
                ];
                continue;
            }
            if (!is_array($belief)) continue;
            $out[] = [
                'hypothesis' => (string) (data_get($belief, 'hypothesis.value', data_get($belief, 'hypothesis', 'unknown'))),
                'confidence' => (float) data_get($belief, 'confidence.value', data_get($belief, 'confidence', 0)),
                'risk' => (float) data_get($belief, 'risk.value', data_get($belief, 'risk', 0)),
                'supporting' => array_values((array) data_get($belief, 'supportingEvidence', data_get($belief, 'supporting', []))),
                'contradicting' => array_values((array) data_get($belief, 'contradictingEvidence', data_get($belief, 'contradicting', []))),
                'action' => (string) data_get($belief, 'decision.action.value', data_get($belief, 'action', 'monitor')),
            ];
        }
        return $out;
    }

    /**
     * @param  array<int, array<string, mixed>|Evidence> $raw
     * @return list<array{type: string, source: string, timestamp: string, reliability: float}>
     */
    private function normaliseEvidence(array $raw): array
    {
        $out = [];
        foreach ($raw as $e) {
            if ($e instanceof Evidence) {
                $out[] = [
                    'type' => $e->type->value,
                    'source' => $e->source,
                    'timestamp' => $e->occurredAt->format(DATE_ATOM),
                    'reliability' => $e->reliability->toFloat(),
                ];
                continue;
            }
            if (!is_array($e)) continue;
            $out[] = [
                'type' => (string) data_get($e, 'type.value', data_get($e, 'type', 'signal')),
                'source' => (string) data_get($e, 'source', 'unknown'),
                'timestamp' => (string) data_get($e, 'timestamp', data_get($e, 'occurred_at', '—')),
                'reliability' => (float) data_get($e, 'reliability.value', data_get($e, 'reliability', 0)),
            ];
        }
        return $out;
    }

    /**
     * Safely test a single webhook channel or all channels.
     * Protected by rate limiting and strict whitelist.
     */
    public function testChannel(Request $request, ?ChannelTestService $testService = null): JsonResponse|RedirectResponse
    {
        $rateLimitEnabled = (bool) config('security-defense.dashboard.rate_limit.enabled', true);
        $maxProbes = (int) config('security-defense.dashboard.rate_limit.max_probes_per_minute', 30);
        $rateLimitKey = 'sec_defense_test_channel:' . ($request->ip() ?? '127.0.0.1');

        if ($rateLimitEnabled && RateLimiter::tooManyAttempts($rateLimitKey, $maxProbes)) {
            $seconds = RateLimiter::availableIn($rateLimitKey);
            $message = "Too many channel test requests. Please wait {$seconds} seconds before probing again.";

            if ($request->wantsJson()) {
                return response()->json(['success' => false, 'message' => $message], 429);
            }

            return back()->with('error_message', $message);
        }

        if ($rateLimitEnabled) {
            RateLimiter::hit($rateLimitKey, 60);
        }

        $request->validate([
            'channel' => 'required|string|in:all,webhook,discord,telegram,mail,database',
        ]);

        $channel = (string) $request->input('channel');
        $service = $testService ?? $this->channelTestService;

        try {
            if ($channel === 'all') {
                $results = $service->testAll();
            } else {
                $results = [$channel => $service->testChannel($channel)];
            }

            if ($request->wantsJson()) {
                return response()->json([
                    'success' => true,
                    'results' => $results,
                ]);
            }

            return back()->with('test_results', $results)->with('status_message', 'Channel connectivity probe completed.');
        } catch (Throwable $e) {
            Log::error('Security Defense dashboard channel probe failed.', [
                'channel' => $channel,
                'ip' => $request->ip(),
                'exception' => $e,
            ]);

            if ($request->wantsJson()) {
                return response()->json([
                    'success' => false,
                    'message' => 'Channel probe failed. Please check server logs.',
                ], 500);
            }

            return back()->with('error_message', 'Channel probe failed. Please check server logs.');
        }
    }

    /**
     * Mark an alert as acknowledged.
     */
    public function acknowledge(SecurityAlert $alert): RedirectResponse
    {
        $alert->acknowledge();

        return back()->with('status_message', "Alert #{$alert->id} acknowledged successfully.");
    }

    /**
     * Mark an alert as resolved.
     */
    public function resolve(SecurityAlert $alert): RedirectResponse
    {
        $alert->resolve();

        return back()->with('status_message', "Alert #{$alert->id} resolved.");
    }

    /**
     * Release an IP from active quarantine.
     */
    public function pardonIp(Request $request, ?IpQuarantineService $quarantineService = null): RedirectResponse
    {
        $request->validate([
            'ip' => 'required|ip',
        ]);

        $ip = (string) $request->input('ip');
        ($quarantineService ?? $this->quarantineService)->pardon($ip);

        return back()->with('status_message', "IP [{$ip}] successfully pardoned and removed from quarantine.");
    }

    /**
     * Permanently whitelist an IP so it is never quarantined again.
     * Persists into the published config file when writable.
     */
    public function whitelistIp(Request $request, ?IpQuarantineService $quarantineService = null): RedirectResponse
    {
        $request->validate([
            'ip' => 'required|ip',
        ]);

        $ip = (string) $request->input('ip');
        $persisted = ($quarantineService ?? $this->quarantineService)->whitelistIp($ip);

        if ($persisted) {
            return back()->with('status_message', "IP [{$ip}] whitelisted permanently and removed from quarantine.");
        }

        return back()->with('error_message', "IP [{$ip}] whitelisted for this session only - config file not writable, changes lost on cache flush.");
    }

    /**
     * Display Database Change Monitoring & Burp Suite Tamper Intelligence.
     */
    public function dataAudits(Request $request)
    {
        $filters = $request->only(['event', 'auditable_type', 'tampered', 'search', 'range']);
        $dateRange = DateRangeFilter::resolve($request);
        $filters['from'] = $dateRange['from'];
        $filters['to'] = $dateRange['to'];
        $audits = $this->auditQueryService->getAudits($filters, 20);
        $stats = $this->auditQueryService->getStats($request->boolean('refresh'));

        return view('security-defense::data-audits', [
            'audits' => $audits,
            'stats' => $stats,
            'filters' => $filters,
            'dateRange' => $dateRange,
        ]);
    }

    /**
     * JSON endpoint for the live blocked-request feed (WAF activity meter).
     */
    public function liveEvents(Request $request): JsonResponse
    {
        $limit = min(max((int) $request->query('limit', 10), 1), 25);

        return response()->json([
            'events' => $this->analyticsService->getLiveBlockedEvents($limit),
            'generated_at' => now()->toIso8601String(),
        ]);
    }

    /**
     * Toggle a dashboard quick-action setting, persisted to the published config.
     * Only whitelisted keys can be toggled (no arbitrary config writes).
     */
    public function toggleSetting(Request $request, ?ConfigWriterService $configWriter = null): RedirectResponse
    {
        $request->validate([
            'key' => 'required|string',
            'value' => 'required|boolean',
        ]);

        $key = (string) $request->input('key');
        $value = (bool) $request->input('value');

        $toggles = [
            'block_headless_clients' => 'middleware.user_agent_anomaly.block_headless_clients',
            'csp_armor' => 'csp_armor.enabled',
            'async_queue' => 'data_audit.queue.enabled',
        ];

        if (!isset($toggles[$key])) {
            return back()->with('error_message', "Unknown quick-action toggle [{$key}].");
        }

        $configKey = $toggles[$key];
        $persisted = ($configWriter ?? app(ConfigWriterService::class))->write([
            $configKey => $value,
        ]);

        $state = $value ? 'enabled' : 'disabled';

        if ($persisted) {
            return back()->with('status_message', "Quick-action [{$key}] {$state} and saved permanently.");
        }

        return back()->with('error_message', "Quick-action [{$key}] {$state} for this session only - config file not writable.");
    }

    /**
     * Display Session Intelligence & Client-Side Compromise Detection.
     */
    public function sessionIntelligence(Request $request)
    {
        $filters = $request->only(['threat_type', 'severity', 'range']);
        $dateRange = DateRangeFilter::resolve($request);
        $filters['from'] = $dateRange['from'];
        $filters['to'] = $dateRange['to'];
        $alerts = $this->sessionQueryService->getThreats($filters, 20);
        $stats = $this->sessionQueryService->getStats($request->boolean('refresh'));

        return view('security-defense::session-intelligence', [
            'alerts' => $alerts,
            'stats' => $stats,
            'filters' => $filters,
            'dateRange' => $dateRange,
        ]);
    }
}
