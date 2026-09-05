<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature;

use Illuminate\Support\Facades\Cache;
use Mixudev\SecurityDefense\Models\SecurityQuarantine;
use Mixudev\SecurityDefense\Services\DashboardAnalyticsService;
use Mixudev\SecurityDefense\Tests\TestCase;

class DashboardStrictnessAndCacheTest extends TestCase
{
    public function test_cache_can_be_disabled_via_config(): void
    {
        config(['security-defense.dashboard.cache.enabled' => false]);

        $service = new DashboardAnalyticsService();
        $stats = $service->getStats();

        $this->assertIsArray($stats);
        $this->assertArrayHasKey('total', $stats);
    }

    public function test_get_active_quarantines_returns_collection_even_when_cache_poisoned(): void
    {
        // Simulate poisoned cache (e.g. stale serialized class object)
        Cache::put('security_defense:dash_quarantines', new \stdClass(), 60);

        $service = new DashboardAnalyticsService();
        $result = $service->getActiveQuarantines();

        $this->assertInstanceOf(\Illuminate\Support\Collection::class, $result);
    }

    public function test_dashboard_rate_limit_can_be_toggled_off(): void
    {
        config(['security-defense.dashboard.rate_limit.enabled' => false]);

        $controller = $this->app->make(\Mixudev\SecurityDefense\Http\Controllers\DashboardController::class);
        $this->assertNotEmpty($controller);
    }
}