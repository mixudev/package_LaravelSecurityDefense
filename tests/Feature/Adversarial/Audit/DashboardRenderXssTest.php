<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature\Adversarial\Audit;

use PHPUnit\Framework\Attributes\DataProvider;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Schema;
use Mixudev\SecurityDefense\Models\SecurityDataAudit;
use Mixudev\SecurityDefense\Support\Traits\HasSecurityAudit;
use Mixudev\SecurityDefense\Tests\TestCase;

class DashboardRenderProbeModel extends Model
{
    use HasSecurityAudit;

    protected $table = 'dashboard_render_probe_models';
    protected $guarded = [];
}

/**
 * End-to-end stored-XSS proof: payloads that survived persistence must render
 * in the dashboard as inert, escaped text — not as markup or script context.
 */
class DashboardRenderXssTest extends TestCase
{
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app['config']->set('app.key', 'base64:7VzK9gG2e+x8UfXoN9uC7x/2j6yD8Hw0Z1A2B3C4D5E=');
        $app['config']->set('security-defense.dashboard.enabled', true);
        $app['config']->set('security-defense.dashboard.local_only', true);
        $app['config']->set('security-defense.dashboard.allowed_ips', ['127.0.0.1', '::1']);
        $app['config']->set('security-defense.dashboard.require_authenticated_user', false);
    }

    protected function setUp(): void
    {
        parent::setUp();
        config()->set('security-defense.data_audit.alert_on_tampering', false);
        config()->set('security-defense.data_audit.queue.enabled', false);

        Schema::create('dashboard_render_probe_models', function (Blueprint $table) {
            $table->id();
            $table->string('name');
            $table->timestamps();
        });

        $this->app['env'] = 'local';
    }

    #[DataProvider('renderPayloadProvider')]
    public function test_stored_payload_renders_inert(string $payload): void
    {
        $this->seedAudit($payload);
        $body = $this->renderDashboard();

        $lower = strtolower($body);
        // Raw executable signatures must not appear anywhere in the response:
        // persistence defangs them and Blade escapes whatever survives.
        foreach (['<script>alert', '<svg onload', 'onerror=alert', 'javascript:alert', '" onmouseover="alert'] as $raw) {
            $this->assertStringNotContainsString($raw, $lower, "Executable signature leaked to dashboard: {$raw}");
        }
    }

    #[DataProvider('renderPayloadProvider')]
    public function test_stored_payload_is_visible_as_text(string $payload): void
    {
        $this->seedAudit($payload);
        $body = $this->renderDashboard();

        // Forensic readability: the payload must still be inspectable, just inert.
        $this->assertStringContainsString('Database Mutation Log', $body);
        $this->assertStringContainsString('View Diff', $body);
    }

    public function test_onclick_json_blob_cannot_break_out_of_js_string(): void
    {
        // If a payload quote ever reached the onclick attribute raw, the
        // JS string would close and the remainder would execute.
        $this->seedAudit("' onclick='alert(1)");
        $body = $this->renderDashboard();

        $this->assertStringNotContainsString("' onclick=", $body);
        $this->assertStringNotContainsString('&#039; onclick=', $body);
        $this->assertStringContainsString('inspectDiff(', $body);
    }

    public function test_script_breakout_cannot_escape_onclick_attribute(): void
    {
        $this->seedAudit('</script><script>alert(1)</script>');
        $body = $this->renderDashboard();

        $this->assertStringNotContainsString('</script><script>alert(1)', $body);
        $this->assertStringNotContainsString('<script>alert(1)</script>', $body);
    }

    public function test_safe_payload_accessor_escapes_markup_for_third_party_renderers(): void
    {
        // Bypass DataAuditService on purpose: a host app may persist raw rows,
        // so the display accessor itself must be the escaping layer.
        $audit = new SecurityDataAudit([
            'payload_snapshot' => [
                '<img src=x onerror=alert(1)>' => '<script>alert(1)</script>',
                'nested' => ['<b onclick=alert(2)>' => 'value"breakout'],
            ],
        ]);

        $safe = $audit->safe_payload;
        $this->assertNotNull($safe);
        $encoded = (string) json_encode($safe);
        $this->assertStringNotContainsString('<script>', $encoded);
        $this->assertStringNotContainsString('<img', $encoded);
        $this->assertStringContainsString('&lt;', $encoded, 'Safe accessor must HTML-escape values.');
        $this->assertStringContainsString('&lt;', (string) array_key_first($safe), 'Attacker-controlled KEYS must be escaped too.');
    }

    public function test_multiple_hostile_rows_render_without_error(): void
    {
        foreach (['<script>a</script>', '<svg onload=b>', "quote'break", 'amp&ersand', '<!--html comment-->'] as $p) {
            $this->seedAudit($p);
        }

        $body = $this->renderDashboard();
        $this->assertStringContainsString('Database Mutation Log', $body);
        $this->assertStringNotContainsString('<script>a</script>', strtolower($body));
    }

    /** @return array<string,array{0:string}> */
    public static function renderPayloadProvider(): array
    {
        return [
            'script' => ['<script>alert(1)</script>'],
            'svg' => ['<svg onload=alert(1)>'],
            'img' => ['<img src=x onerror=alert(1)>'],
            'quote attr' => ['" onmouseover="alert(1)'],
            'js scheme' => ['javascript:alert(document.cookie)'],
            'unicode' => ['<script>al\u0065rt(2)</script>'],
            'html comment' => ['<!--<script>alert(3)</script>-->'],
            'cdata' => ['<![CDATA[<script>alert(4)</script>]]>'],
        ];
    }

    private function seedAudit(string $payload): SecurityDataAudit
    {
        $request = Request::create('/profile/update', 'POST', ['comment' => $payload], [], [], [
            'HTTP_USER_AGENT' => $payload,
        ]);
        $this->app->instance('request', $request);

        $model = DashboardRenderProbeModel::create(['name' => 'probe']);

        $audit = SecurityDataAudit::query()
            ->where('auditable_type', DashboardRenderProbeModel::class)
            ->where('auditable_id', (string) $model->getKey())
            ->first();
        $this->assertNotNull($audit);

        return $audit;
    }

    private function renderDashboard(): string
    {
        $response = $this->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
            ->get('/security-defense/data-audits');
        $this->assertSame(200, $response->getStatusCode());

        return (string) $response->getContent();
    }
}
