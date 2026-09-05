<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature;

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Mixudev\SecurityDefense\Console\Commands\PruneSecurityDataCommand;
use Mixudev\SecurityDefense\Middleware\ContentSecurityPolicyArmor;
use Mixudev\SecurityDefense\Models\SecurityAlert;
use Mixudev\SecurityDefense\Models\SecurityDataAudit;
use Mixudev\SecurityDefense\Tests\TestCase;

class PruneAndCspArmorTest extends TestCase
{
    public function test_safe_payload_attribute_escapes_xss_content(): void
    {
        $audit = new SecurityDataAudit([
            'payload_snapshot' => [
                'username' => '<script>alert("pwned")</script>',
                'profile' => [
                    'bio' => '<img src=x onerror=alert(1)>',
                ],
            ],
        ]);

        $safe = $audit->safe_payload;

        $this->assertStringNotContainsString('<script>', $safe['username']);
        $this->assertStringContainsString('&lt;script&gt;', $safe['username']);
        $this->assertStringNotContainsString('<img', $safe['profile']['bio']);
        $this->assertStringContainsString('&lt;img', $safe['profile']['bio']);
    }

    public function test_csp_armor_middleware_injects_headers_and_nonce(): void
    {
        $middleware = new ContentSecurityPolicyArmor();
        $request = Request::create('/test', 'GET');

        $response = $middleware->handle($request, function ($req) {
            return new Response('<html><body>Hello</body></html>', 200, ['Content-Type' => 'text/html']);
        });

        $this->assertTrue($response->headers->has('Content-Security-Policy'));
        $cspHeader = $response->headers->get('Content-Security-Policy');
        $this->assertStringContainsString("default-src 'self'", $cspHeader);
        $this->assertStringContainsString('nonce-', $cspHeader);
    }

    public function test_prune_command_runs_successfully(): void
    {
        SecurityDataAudit::create([
            'event' => 'updated',
            'auditable_type' => 'App\Models\User',
            'auditable_id' => '1',
            'ip_address' => '127.0.0.1',
            'request_method' => 'POST',
            'is_tampered' => false,
            'created_at' => now()->subDays(40),
        ]);

        SecurityDataAudit::create([
            'event' => 'updated',
            'auditable_type' => 'App\Models\User',
            'auditable_id' => '2',
            'ip_address' => '127.0.0.1',
            'request_method' => 'POST',
            'is_tampered' => true,
            'created_at' => now()->subDays(100),
        ]);

        $this->artisan('security-defense:prune', ['--dry-run' => true])
            ->assertSuccessful();

        $this->artisan('security-defense:prune')
            ->assertSuccessful();

        $this->assertEquals(0, SecurityDataAudit::count());
    }
}
