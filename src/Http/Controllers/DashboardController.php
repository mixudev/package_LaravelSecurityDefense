<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\RateLimiter;
use Mixudev\SecurityDefense\Models\SecurityAlert;
use Mixudev\SecurityDefense\Models\SecurityQuarantine;
use Mixudev\SecurityDefense\Services\ChannelTestService;
use Mixudev\SecurityDefense\Services\IpQuarantineService;
use Throwable;

/**
 * Enterprise Monitoring Dashboard controller.
 * Restricted strictly to authorized local environments.
 */
class DashboardController extends Controller
{
    /**
     * Display the Security Defense monitoring dashboard.
     */
    public function index(Request $request, ChannelTestService $testService)
    {
        // 1. Metric counters
        $stats = [
            'total' => SecurityAlert::query()->count(),
            'new' => SecurityAlert::query()->new()->count(),
            'acknowledged' => SecurityAlert::query()->acknowledged()->count(),
            'resolved' => SecurityAlert::query()->resolved()->count(),
            'critical' => SecurityAlert::query()->severity('critical')->count(),
            'high' => SecurityAlert::query()->severity('high')->count(),
            'medium' => SecurityAlert::query()->severity('medium')->count(),
            'low' => SecurityAlert::query()->severity('low')->count(),
        ];

        // 2. Filterable recent alerts
        $alertsQuery = SecurityAlert::query()->latest();

        if ($request->filled('status')) {
            $alertsQuery->where('status', (string) $request->input('status'));
        }

        if ($request->filled('severity')) {
            $alertsQuery->where('severity', (string) $request->input('severity'));
        }

        if ($request->filled('threat_type')) {
            $alertsQuery->where('threat_type', (string) $request->input('threat_type'));
        }

        $alerts = $alertsQuery->paginate(15)->withQueryString();

        // 3. Threat distribution by type
        $threatDistribution = SecurityAlert::query()
            ->selectRaw('threat_type, count(*) as count')
            ->groupBy('threat_type')
            ->orderByDesc('count')
            ->limit(8)
            ->pluck('count', 'threat_type')
            ->all();

        // 4. Active IP Quarantines (DB-backed or cache fallback)
        $quarantinedIps = [];
        try {
            if (class_exists(SecurityQuarantine::class)) {
                $quarantinedIps = SecurityQuarantine::query()->active()->latest()->limit(20)->get();
            }
        } catch (Throwable) {
            $quarantinedIps = collect([]);
        }

        // 5. Alert channels status
        $channelsStatus = $testService->getChannelsStatus();

        return view('security-defense::dashboard', [
            'stats' => $stats,
            'alerts' => $alerts,
            'threatDistribution' => $threatDistribution,
            'quarantinedIps' => $quarantinedIps,
            'channelsStatus' => $channelsStatus,
            'filters' => $request->only(['status', 'severity', 'threat_type']),
        ]);
    }

    /**
     * Safely test a single webhook channel or all channels.
     * Protected by rate limiting and strict whitelist.
     */
    public function testChannel(Request $request, ChannelTestService $testService): JsonResponse|RedirectResponse
    {
        // Rate limit: max 10 tests per minute per IP
        $rateLimitKey = 'sec_defense_test_channel:' . ($request->ip() ?? '127.0.0.1');
        if (RateLimiter::tooManyAttempts($rateLimitKey, 10)) {
            $seconds = RateLimiter::availableIn($rateLimitKey);
            $message = "Too many channel test requests. Please wait {$seconds} seconds before probing again.";

            if ($request->wantsJson()) {
                return response()->json(['success' => false, 'message' => $message], 429);
            }

            return back()->with('error_message', $message);
        }

        RateLimiter::hit($rateLimitKey, 60);

        $request->validate([
            'channel' => 'required|string|in:all,webhook,discord,telegram,mail,database',
        ]);

        $channel = (string) $request->input('channel');

        try {
            if ($channel === 'all') {
                $results = $testService->testAll();
            } else {
                $results = [$channel => $testService->testChannel($channel)];
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
    public function pardonIp(Request $request, IpQuarantineService $quarantineService): RedirectResponse
    {
        $request->validate([
            'ip' => 'required|ip',
        ]);

        $ip = (string) $request->input('ip');
        $quarantineService->pardon($ip);

        return back()->with('status_message', "IP [{$ip}] successfully pardoned and removed from quarantine.");
    }

    /**
     * Display Database Change Monitoring & Burp Suite Tamper Intelligence.
     */
    public function dataAudits(Request $request)
    {
        $query = \Mixudev\SecurityDefense\Models\SecurityDataAudit::query()->latest();

        if ($request->filled('event')) {
            $query->where('event', (string) $request->input('event'));
        }

        if ($request->filled('auditable_type')) {
            $query->where('auditable_type', 'like', '%' . (string) $request->input('auditable_type') . '%');
        }

        if ($request->filled('tampered')) {
            $tampered = $request->input('tampered');
            if ($tampered === '1' || $tampered === 'true') {
                $query->where('is_tampered', true);
            } elseif ($tampered === '0' || $tampered === 'false') {
                $query->where('is_tampered', false);
            }
        }

        if ($request->filled('search')) {
            $search = (string) $request->input('search');
            $query->where(function ($q) use ($search) {
                $q->where('auditable_id', 'like', "%{$search}%")
                    ->orWhere('actor_id', 'like', "%{$search}%")
                    ->orWhere('ip_address', 'like', "%{$search}%")
                    ->orWhere('request_url', 'like', "%{$search}%");
            });
        }

        $audits = $query->paginate(20)->withQueryString();

        $stats = [
            'total' => \Mixudev\SecurityDefense\Models\SecurityDataAudit::query()->count(),
            'tampered' => \Mixudev\SecurityDefense\Models\SecurityDataAudit::query()->where('is_tampered', true)->count(),
            'today' => \Mixudev\SecurityDefense\Models\SecurityDataAudit::query()->whereDate('created_at', now()->toDateString())->count(),
            'unique_actors' => \Mixudev\SecurityDefense\Models\SecurityDataAudit::query()->whereNotNull('actor_id')->distinct('actor_id')->count('actor_id'),
        ];

        return view('security-defense::data-audits', [
            'audits' => $audits,
            'stats' => $stats,
            'filters' => $request->only(['event', 'auditable_type', 'tampered', 'search']),
        ]);
    }

    /**
     * Display Session Intelligence & Client-Side Compromise Detection.
     */
    public function sessionIntelligence(Request $request)
    {
        $sessionThreatTypes = [
            'session_hijack_suspected',
            'suspicious_velocity_scraping',
            'header_inconsistency_bot',
            'impossible_travel',
        ];

        $threatsQuery = SecurityAlert::query()
            ->whereIn('threat_type', $sessionThreatTypes)
            ->latest();

        if ($request->filled('threat_type')) {
            $threatsQuery->where('threat_type', (string) $request->input('threat_type'));
        }

        if ($request->filled('severity')) {
            $threatsQuery->where('severity', (string) $request->input('severity'));
        }

        $alerts = $threatsQuery->paginate(20)->withQueryString();

        $stats = [
            'total_session_threats' => SecurityAlert::query()->whereIn('threat_type', $sessionThreatTypes)->count(),
            'hijacks_detected' => SecurityAlert::query()->where('threat_type', 'session_hijack_suspected')->count(),
            'velocity_spikes' => SecurityAlert::query()->where('threat_type', 'suspicious_velocity_scraping')->count(),
            'header_anomalies' => SecurityAlert::query()->where('threat_type', 'header_inconsistency_bot')->count(),
        ];

        return view('security-defense::session-intelligence', [
            'alerts' => $alerts,
            'stats' => $stats,
            'filters' => $request->only(['threat_type', 'severity']),
        ]);
    }
}
