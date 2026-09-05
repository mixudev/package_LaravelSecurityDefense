<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature;

use Illuminate\Support\Facades\Event;
use Mixudev\SecurityDefense\Models\SecurityAlert;
use Mixudev\SecurityDefense\Tests\TestCase;

class LiveEventsDashboardTest extends TestCase
{
    protected function defineRoutes($router)
    {
        $router->get('/test-live-events', function (\Illuminate\Http\Request $request) {
            $limit = min(max((int) $request->query('limit', 5), 1), 25);

            return response()->json([
                'events' => app(\Mixudev\SecurityDefense\Services\DashboardAnalyticsService::class)->getLiveBlockedEvents($limit),
            ]);
        });
    }

    public function test_live_events_endpoint_returns_latest_blocked_alerts(): void
    {
        SecurityAlert::query()->create([
            'severity' => 'critical',
            'threat_type' => 'sqli',
            'fingerprint' => 'fp1',
            'status' => 'new',
            'rule_identifier' => 'payload_injection',
            'metadata' => [
                'ip' => '203.0.113.10',
                'url' => '/admin/login',
                'method' => 'POST',
                'user_agent' => 'sqlmap/1.7',
            ],
        ]);

        SecurityAlert::query()->create([
            'severity' => 'high',
            'threat_type' => 'xss',
            'fingerprint' => 'fp2',
            'status' => 'new',
            'rule_identifier' => 'payload_injection',
            'metadata' => [
                'ip' => '198.51.100.22',
                'url' => '/search?q=<script>',
                'method' => 'GET',
                'user_agent' => 'Mozilla/5.0',
            ],
        ]);

        $this->get('/test-live-events')
            ->assertOk()
            ->assertJsonCount(2, 'events')
            ->assertJsonPath('events.0.threat_type', 'sqli')
            ->assertJsonPath('events.0.ip', '203.0.113.10')
            ->assertJsonPath('events.0.method', 'POST')
            ->assertJsonPath('events.1.threat_type', 'xss')
            ->assertJsonPath('events.1.url', '/search?q=[script]');
    }

    public function test_live_events_returns_empty_when_no_alerts(): void
    {
        SecurityAlert::query()->truncate();

        $this->get('/test-live-events')
            ->assertOk()
            ->assertJsonCount(0, 'events');
    }

    public function test_live_events_honors_limit(): void
    {
        Event::fake();

        for ($i = 1; $i <= 5; $i++) {
            SecurityAlert::query()->create([
                'severity' => 'low',
                'threat_type' => 'scan',
                'fingerprint' => 'fp' . $i,
                'status' => 'new',
                'metadata' => [],
            ]);
        }

        $this->get('/test-live-events?limit=3')
            ->assertOk()
            ->assertJsonCount(3, 'events');
    }
}