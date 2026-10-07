<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature;

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Mixudev\SecurityDefense\Console\Commands\PruneSecurityDataCommand;
use Mixudev\SecurityDefense\Middleware\ContentSecurityPolicyArmor;
use Mixudev\SecurityDefense\Models\SecurityAlert;
use Mixudev\SecurityDefense\Models\SecurityDataAudit;
use Mixudev\SecurityDefense\Support\Sanitizer;
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
        $this->assertDoesNotMatchRegularExpression("/script-src[^;]*'unsafe-inline'/", $cspHeader);
    }

    public function test_csp_armor_skips_non_html_responses(): void
    {
        $middleware = new ContentSecurityPolicyArmor();

        // A JSON response must never receive a CSP header.
        $json = $middleware->handle(Request::create('/api', 'GET'), fn () => new Response('{}', 200, ['Content-Type' => 'application/json']));
        $this->assertFalse($json->headers->has('Content-Security-Policy'), 'JSON tidak boleh menerima CSP.');

        // A bodyless response has nothing to protect; a CSP header there wastes
        // bytes and can confuse shared caches keyed on 204/304.
        $noContent = $middleware->handle(Request::create('/x', 'GET'), fn () => new Response('', 204));
        $this->assertFalse($noContent->headers->has('Content-Security-Policy'), 'Respons 204 tidak boleh menerima CSP.');

        $image = $middleware->handle(Request::create('/x', 'GET'), fn () => new Response('binary', 200, ['Content-Type' => 'image/png']));
        $this->assertFalse($image->headers->has('Content-Security-Policy'), 'Gambar tidak boleh menerima CSP.');
    }

    public function test_csp_armor_clears_a_conflicting_opposite_mode_header(): void
    {
        config()->set('security-defense.csp_armor.report_only', true);
        $middleware = new ContentSecurityPolicyArmor();

        // report_only=true but downstream set an ENFORCED policy: sending only the
        // report-only header would silently drop enforcement.
        $response = $middleware->handle(Request::create('/x', 'GET'), function () {
            return new Response('<html></html>', 200, [
                'Content-Type' => 'text/html',
                'Content-Security-Policy' => "default-src 'none'",
            ]);
        });

        $this->assertTrue($response->headers->has('Content-Security-Policy-Report-Only'));
    }

    public function test_audit_diff_escapes_stored_xss_values_before_inner_html(): void
    {
        $view = file_get_contents(dirname(__DIR__, 2) . '/resources/views/components/audits/audit-diff-modal.blade.php');

        $this->assertIsString($view);
        $this->assertStringContainsString('escapeHtml(JSON.stringify(oldVals[f]))', $view);
        $this->assertStringContainsString('escapeHtml(JSON.stringify(newVals[f]))', $view);
        $this->assertStringNotContainsString('${oldVals[f]}', $view);
        $this->assertStringNotContainsString('${newVals[f]}', $view);
    }

    public function test_audit_snapshot_defangs_stored_executable_payloads(): void
    {
        $request = Request::create('/submit', 'POST', [
            'comment' => '<script>alert(1)</script><img src=x onerror=alert(2)>',
            'nested' => ['value' => 'javascript:alert(3)'],
            'password' => 'do-not-store',
        ]);

        $snapshot = (new \Mixudev\SecurityDefense\Services\AuditPayloadSanitizer())
            ->resolvePayloadSnapshot($request);

        $json = json_encode($snapshot, JSON_THROW_ON_ERROR);
        $this->assertStringNotContainsString('<script>', $json);
        $this->assertStringNotContainsString('<img', $json);
        $this->assertStringNotContainsString('javascript:', $json);
        $this->assertStringContainsString('[REDACTED]', $json);
        // Defanging must not mangle ordinary comparison/operator text.
        $defanged = Sanitizer::clean(['q' => 'age<30 and age>18']);
        $this->assertSame('age<30 and age>18', $defanged['q']);
    }

    public function test_audit_metadata_context_is_defanged_before_persistence(): void
    {
        $model = new class extends \Illuminate\Database\Eloquent\Model {
            protected $table = 'audit_test_models';
            protected $guarded = [];
        };

        $request = Request::create('/<script>alert(1)</script>', 'POST');
        $request->headers->set('User-Agent', '<img src=x onerror=alert(1)>');
        $service = new \Mixudev\SecurityDefense\Services\DataAuditService($request);

        $audit = $service->recordMutation($model, \Mixudev\SecurityDefense\Models\SecurityDataAudit::EVENT_CREATED);

        $this->assertNotNull($audit, 'Audit metadata must be persisted when data auditing is enabled.');
        $this->assertStringNotContainsString('<img', (string) $audit->user_agent);
        $this->assertStringNotContainsString('<script>', (string) $audit->request_url);
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
