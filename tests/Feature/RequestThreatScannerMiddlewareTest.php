<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Mixudev\SecurityDefense\Middleware\RequestThreatScanner;
use Mixudev\SecurityDefense\Models\SecurityAlert;
use Mixudev\SecurityDefense\Services\IpQuarantineService;
use Mixudev\SecurityDefense\Tests\TestCase;

class RequestThreatScannerMiddlewareTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        Route::middleware(RequestThreatScanner::class)->group(function () {
            Route::get('/test-route', static fn () => response()->json(['status' => 'ok']));
            Route::get('/.env', static fn () => response()->json(['status' => 'secret_env']));
            Route::post('/test-submit', static fn (Request $request) => response()->json(['received' => $request->all()]));
            Route::post('/api/webhook-incoming', static fn () => response()->json(['status' => 'bypassed']));
        });
    }

    public function test_clean_request_passes_through(): void
    {
        $response = $this->get('/test-route?q=normal-search-term');

        $response->assertStatus(200);
        $response->assertJson(['status' => 'ok']);
    }

    public function test_it_blocks_sqli_query_payload_and_auto_jails(): void
    {
        config()->set('security-defense.middleware.quarantine.enabled', true);
        config()->set('security-defense.middleware.quarantine.auto_jail_on_critical', true);
        config()->set('security-defense.middleware.quarantine.whitelist', []); // empty whitelist for test

        $response = $this->withServerVariables(['REMOTE_ADDR' => '192.0.2.99'])
            ->get('/test-route?q=' . urlencode("' OR 1=1--"));

        $response->assertStatus(403);

        // Verify alert was persisted in database
        $this->assertDatabaseHas('security_alerts', [
            'threat_type' => 'payload_injection',
            'severity' => 'critical',
        ]);

        // Verify IP was quarantined
        $quarantine = app(IpQuarantineService::class);
        $this->assertTrue($quarantine->isQuarantined('192.0.2.99'));

        // Next request from this quarantined IP should be immediately rejected with HTTP 429
        $secondResponse = $this->withServerVariables(['REMOTE_ADDR' => '192.0.2.99'])
            ->get('/test-route');

        $secondResponse->assertStatus(429);
    }

    public function test_it_blocks_xss_in_json_body_with_json_response(): void
    {
        $response = $this->postJson('/test-submit', [
            'comment' => '<script>alert(document.cookie)</script>',
        ]);

        $response->assertStatus(403);
        $response->assertJsonStructure(['error', 'message', 'threat_id']);
    }

    public function test_it_blocks_path_reconnaissance_probe(): void
    {
        $response = $this->get('/.env');

        $response->assertStatus(403);
    }

    public function test_it_blocks_automated_scanner_user_agent(): void
    {
        $response = $this->withHeaders([
            'User-Agent' => 'sqlmap/1.7#stable',
        ])->get('/test-route');

        $response->assertStatus(403);
    }

    public function test_it_allows_excluded_paths_to_bypass_scanner(): void
    {
        config()->set('security-defense.middleware.payload_scanner.excluded_paths', [
            'api/webhook-incoming',
        ]);

        $response = $this->postJson('/api/webhook-incoming', [
            'payload' => "UNION SELECT * FROM raw_events",
        ]);

        $response->assertStatus(200);
        $response->assertJson(['status' => 'bypassed']);
    }
}
