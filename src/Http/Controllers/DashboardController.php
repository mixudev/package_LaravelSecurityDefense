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
}
