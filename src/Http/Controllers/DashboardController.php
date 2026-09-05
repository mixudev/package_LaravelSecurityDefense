<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\RateLimiter;
use Mixudev\SecurityDefense\Models\SecurityAlert;
use Mixudev\SecurityDefense\Services\ChannelTestService;
use Mixudev\SecurityDefense\Services\ConfigWriterService;
use Mixudev\SecurityDefense\Services\DashboardAnalyticsService;
use Mixudev\SecurityDefense\Services\DataAuditQueryService;
use Mixudev\SecurityDefense\Services\IpQuarantineService;
use Mixudev\SecurityDefense\Services\SessionIntelligenceQueryService;
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

        $filters = $request->only(['status', 'severity', 'threat_type']);
        $alerts = $this->analyticsService->getFilteredAlerts($filters, 15);
        $liveEvents = $this->analyticsService->getLiveBlockedEvents(10);

        return view('security-defense::dashboard', [
            'stats' => $stats,
            'alerts' => $alerts,
            'liveEvents' => $liveEvents,
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
            if ($request->wantsJson()) {
                return response()->json([
                    'success' => false,
                    'message' => $e->getMessage(),
                ], 400);
            }

            return back()->with('error_message', 'Test failed: ' . $e->getMessage());
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
        $filters = $request->only(['event', 'auditable_type', 'tampered', 'search']);
        $audits = $this->auditQueryService->getAudits($filters, 20);
        $stats = $this->auditQueryService->getStats($request->boolean('refresh'));

        return view('security-defense::data-audits', [
            'audits' => $audits,
            'stats' => $stats,
            'filters' => $filters,
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
        $filters = $request->only(['threat_type', 'severity']);
        $alerts = $this->sessionQueryService->getThreats($filters, 20);
        $stats = $this->sessionQueryService->getStats($request->boolean('refresh'));

        return view('security-defense::session-intelligence', [
            'alerts' => $alerts,
            'stats' => $stats,
            'filters' => $filters,
        ]);
    }
}
