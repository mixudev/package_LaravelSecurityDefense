<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Mixudev\SecurityDefense\Models\SecurityAlert;
use Mixudev\SecurityDefense\Models\SecurityDataAudit;
use Mixudev\SecurityDefense\Services\DataAuditQueryService;
use Mixudev\SecurityDefense\Services\DashboardAnalyticsService;
use Mixudev\SecurityDefense\Services\SessionIntelligenceQueryService;
use Mixudev\SecurityDefense\Support\DateRangeFilter;
use Mixudev\SecurityDefense\Tests\TestCase;

class DateRangeFilterTest extends TestCase
{
    public function test_resolve_30d_default(): void
    {
        $request = Request::create('/security-defense/data-audits');
        $range = DateRangeFilter::resolve($request);

        $this->assertSame('30d', $range['preset']);
        $this->assertNotNull($range['from']);
        $this->assertNotNull($range['to']);
        $this->assertTrue($range['from']->lte(now()));
        $this->assertTrue($range['to']->gte(now()));
    }

    public function test_resolve_today_preset(): void
    {
        $request = Request::create('/security-defense/data-audits?range=today');
        $range = DateRangeFilter::resolve($request);

        $this->assertSame('today', $range['preset']);
        $this->assertSame(now()->startOfDay()->toDateString(), $range['from']->toDateString());
        $this->assertSame(now()->endOfDay()->toDateString(), $range['to']->toDateString());
    }

    public function test_resolve_invalid_preset_falls_back_to_30d(): void
    {
        $request = Request::create('/security-defense/data-audits?range=year');
        $range = DateRangeFilter::resolve($request);

        $this->assertSame('30d', $range['preset']);
    }

    public function test_audit_query_filters_by_date_range(): void
    {
        // Old audit (61 days ago) — outside 30d window.
        SecurityDataAudit::query()->create([
            'event' => 'created',
            'auditable_type' => 'App\\Models\\User',
            'auditable_id' => 1,
            'request_method' => 'POST',
            'request_url' => '/old',
            'ip_address' => '10.0.0.1',
            'is_tampered' => false,
            'created_at' => now()->subDays(61),
        ]);

        // New audit (2 days ago) — inside window.
        SecurityDataAudit::query()->create([
            'event' => 'updated',
            'auditable_type' => 'App\\Models\\User',
            'auditable_id' => 2,
            'request_method' => 'PUT',
            'request_url' => '/new',
            'ip_address' => '10.0.0.2',
            'is_tampered' => false,
            'created_at' => now()->subDays(2),
        ]);

        $range = DateRangeFilter::resolve(Request::create('/?range=30d'));
        $audits = (new DataAuditQueryService())->getAudits([
            'from' => $range['from'],
            'to' => $range['to'],
        ], 20);

        $this->assertSame(1, $audits->total());
        $this->assertSame('/new', $audits->first()->request_url);
    }

    public function test_session_query_filters_by_date_range(): void
    {
        SecurityAlert::query()->create([
            'severity' => 'high',
            'threat_type' => 'session_hijack_suspected',
            'fingerprint' => 'fp-old',
            'status' => 'new',
            'created_at' => now()->subDays(61),
        ]);

        SecurityAlert::query()->create([
            'severity' => 'critical',
            'threat_type' => 'session_hijack_suspected',
            'fingerprint' => 'fp-new',
            'status' => 'new',
            'created_at' => now()->subDays(1),
        ]);

        $range = DateRangeFilter::resolve(Request::create('/?range=30d'));
        $threats = (new SessionIntelligenceQueryService())->getThreats([
            'from' => $range['from'],
            'to' => $range['to'],
        ], 20);

        $this->assertSame(1, $threats->total());
        $this->assertSame('fp-new', $threats->first()->fingerprint);
    }

    public function test_dashboard_alerts_filtered_by_date_range(): void
    {
        SecurityAlert::query()->create([
            'severity' => 'low',
            'threat_type' => 'scan',
            'fingerprint' => 'old-fp',
            'status' => 'new',
            'created_at' => now()->subDays(61),
        ]);

        SecurityAlert::query()->create([
            'severity' => 'high',
            'threat_type' => 'sqli',
            'fingerprint' => 'new-fp',
            'status' => 'new',
            'created_at' => now(),
        ]);

        $range = DateRangeFilter::resolve(Request::create('/?range=today'));
        $alerts = (new DashboardAnalyticsService())->getFilteredAlerts([
            'from' => $range['from'],
            'to' => $range['to'],
        ], 15);

        $this->assertSame(1, $alerts->total());
        $this->assertSame('new-fp', $alerts->first()->fingerprint);
    }
}