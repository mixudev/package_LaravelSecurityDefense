<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Mixudev\SecurityDefense\Middleware\RequestThreatScanner;
use Mixudev\SecurityDefense\Services\IpQuarantineService;
use Mixudev\SecurityDefense\Tests\TestCase;

class RequestThreatScannerEnterpriseTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        Route::middleware(RequestThreatScanner::class)->group(function () {
            Route::get('/home', static fn () => response()->json(['ok' => true]));
            Route::get('/search', static fn (Request $request) => response()->json(['q' => $request->query('q')]));
            Route::post('/api/data', static fn (Request $request) => response()->json(['received' => $request->all()]));
            // Route that accepts TRACE so the middleware runs and can block it.
            Route::match(['TRACE'], '/trace', static fn () => response()->json(['ok' => true]));
        });
    }

    public function test_dry_get_without_query_or_body_is_not_scanned(): void
    {
        // Ordinary GET with no input: fast-path skips the regex payload scan.
        // Payload-injection block action still applies, but there is nothing to match,
        // and the request passes through cleanly at near-zero CPU cost.
        $response = $this->get('/home');
        $response->assertStatus(200);
        $response->assertJson(['ok' => true]);
    }

    public function test_query_payload_is_still_scanned_and_blocked_when_present(): void
    {
        $response = $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.5'])
            ->get('/search?q=' . urlencode("UNION SELECT 1--"));

        $response->assertStatus(403);
    }

    public function test_trace_method_is_blocked_unconditionally(): void
    {
        config()->set('security-defense.enabled', true);

        $response = $this->call('TRACE', '/trace');
        $this->assertSame(403, $response->getStatusCode());
    }

    public function test_request_flood_exceeding_cap_jails_ip(): void
    {
        // Configure a tiny cap so a handful of rapid requests exceed the window.
        config()->set('security-defense.middleware.request_flood', [
            'enabled' => true,
            'max_requests_per_second' => 2,
            'window' => 1,
            'jail_after_exceeding' => 1,
        ]);
        config()->set('security-defense.middleware.quarantine.enabled', true);
        config()->set('security-defense.middleware.quarantine.whitelist', []);

        $ip = '198.51.100.60';

        // Exhaust the cheap flood counter (2 allowed) then trigger jail on 3rd/4th.
        $this->withServerVariables(['REMOTE_ADDR' => $ip])->get('/home');
        $this->withServerVariables(['REMOTE_ADDR' => $ip])->get('/home');
        // Third + fourth exceed the cap and jail the IP.
        $this->withServerVariables(['REMOTE_ADDR' => $ip])->get('/home');
        $this->withServerVariables(['REMOTE_ADDR' => $ip])->get('/home');

        $quarantine = app(IpQuarantineService::class);
        $this->assertTrue($quarantine->isQuarantined($ip));
    }

    public function test_expanded_scanner_user_agent_is_blocked(): void
    {
        $response = $this->withHeaders(['User-Agent' => 'ffuf/v2.1.0'])
            ->get('/home');

        $response->assertStatus(403);
    }
}
