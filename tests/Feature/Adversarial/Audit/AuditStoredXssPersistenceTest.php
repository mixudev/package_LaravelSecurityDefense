<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature\Adversarial\Audit;

use PHPUnit\Framework\Attributes\DataProvider;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Schema;
use Mixudev\SecurityDefense\Models\SecurityDataAudit;
use Mixudev\SecurityDefense\Services\DataAuditService;
use Mixudev\SecurityDefense\Support\Traits\HasSecurityAudit;
use Mixudev\SecurityDefense\Tests\TestCase;

class AuditXssProbeModel extends Model
{
    use HasSecurityAudit;

    protected $table = 'audit_xss_probe_models';
    protected $guarded = [];
}

/**
 * Attacker POV: hostile payloads delivered through every request channel
 * (user agent, URL path, query, form body, JSON, nested arrays) must be
 * defanged BEFORE they reach any security_data_audits column.
 */
class AuditStoredXssPersistenceTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        config()->set('security-defense.data_audit.alert_on_tampering', false);
        config()->set('security-defense.data_audit.queue.enabled', false);

        Schema::create('audit_xss_probe_models', function (Blueprint $table) {
            $table->id();
            $table->string('name');
            $table->timestamps();
        });
    }

    #[DataProvider('payloadProvider')]
    public function test_user_agent_payload_is_defanged_before_persist(string $payload): void
    {
        $audit = $this->persistWithUserAgent($payload);

        $this->assertNotNull($audit, 'Audit row must persist (fail-safe swallowed an error).');
        $stored = (string) $audit->user_agent;
        $this->assertNoExecutableMarkup($stored);
    }

    #[DataProvider('payloadProvider')]
    public function test_payload_snapshot_is_defanged_before_persist(string $payload): void
    {
        $audit = $this->persistWithBody(['comment' => $payload]);

        $this->assertNotNull($audit);
        $this->assertNotNull($audit->payload_snapshot, 'Body must reach the snapshot.');
        $this->assertNoExecutableMarkup((string) json_encode($audit->payload_snapshot));
    }

    #[DataProvider('payloadProvider')]
    public function test_nested_body_payload_is_defanged_before_persist(string $payload): void
    {
        $audit = $this->persistWithBody([
            'user' => ['metadata' => ['profile' => ['bio' => $payload]]],
        ]);

        $this->assertNotNull($audit);
        $this->assertNotNull($audit->payload_snapshot, 'Nested body must reach the snapshot.');
        $this->assertNoExecutableMarkup((string) json_encode($audit->payload_snapshot));
    }

    public function test_json_unicode_escape_payload_is_defanged_after_decode(): void
    {
        // \u003cscript\u003e survives raw storage as inert text but becomes live
        // markup once a consumer decodes it; the request decoder runs first, so
        // what lands in the row must already be defanged real markup.
        $raw = '{"q":"\\u003cscript\\u003ealert(1)\\u003c/script\\u003e"}';
        $request = Request::create('/profile/update', 'POST', [], [], [], [
            'CONTENT_TYPE' => 'application/json',
            'HTTP_USER_AGENT' => 'x',
        ], $raw);
        $this->app->instance('request', $request);

        $audit = $this->persistModel();

        $this->assertNotNull($audit);
        // Non-null snapshot proves the JSON body was actually parsed and scanned;
        // a null would make this test pass vacuously.
        $this->assertNotNull($audit->payload_snapshot, 'JSON body must reach the snapshot.');
        $this->assertStringContainsString('[script]', (string) json_encode($audit->payload_snapshot));
        $this->assertNoExecutableMarkup((string) json_encode($audit->payload_snapshot));
    }

    public function test_query_string_payload_never_reaches_request_url(): void
    {
        $request = Request::create('/search?q=<script>alert(1)</script>&x=%3Csvg%20onload=alert(1)%3E', 'GET');
        $this->app->instance('request', $request);

        $audit = $this->persistModel();

        $this->assertNotNull($audit);
        $this->assertStringNotContainsString('q=', (string) $audit->request_url, 'Query strings must not be persisted.');
        $this->assertNoExecutableMarkup((string) $audit->request_url);
    }

    public function test_hostile_path_segment_is_defanged_in_request_url(): void
    {
        $request = Request::create('/profile/<script>alert(1)</script>', 'GET');
        $this->app->instance('request', $request);

        $audit = $this->persistModel();

        $this->assertNotNull($audit);
        $this->assertNoExecutableMarkup((string) $audit->request_url);
    }

    public function test_deeply_nested_payload_hits_depth_bound_instead_of_leaking_raw(): void
    {
        $audit = $this->persistWithBody([
            'a' => ['b' => ['c' => ['d' => ['e' => ['f' => '<script>alert(1)</script>']]]]],
        ]);

        $this->assertNotNull($audit);
        $encoded = (string) json_encode($audit->payload_snapshot);
        $this->assertNoExecutableMarkup($encoded);
        $this->assertStringContainsString('_truncated_depth', $encoded, 'Depth bound must truncate, not drop silently.');
    }

    public function test_all_persisted_columns_are_free_of_executable_markup(): void
    {
        $audit = $this->persistWithBody(['comment' => '<script>alert(1)</script>']);

        $this->assertNotNull($audit);
        $fresh = SecurityDataAudit::query()->findOrFail($audit->id);
        $this->assertNoExecutableMarkup((string) json_encode($fresh->getAttributes()));
    }

    /** @return array<string,array{0:string}> */
    public static function payloadProvider(): array
    {
        return [
            'script tag' => ['<script>alert(1)</script>'],
            'img onerror' => ['<img src=x onerror=alert(1)>'],
            'svg onload' => ['<svg onload=alert(document.cookie)>'],
            'iframe' => ['<iframe src=javascript:alert(1)></iframe>'],
            'javascript scheme' => ['javascript:alert(1)'],
            'breakout attr' => ['" onmouseover="alert(1)'],
            'single quote breakout' => ["' onfocus='alert(1)"],
            'closing tag' => ['</script><script>alert(1)</script>'],
            'style tag' => ['<style>@import"x";</style>'],
            'form tag' => ['<form action=javascript:alert(1)><input type=submit>'],
            'meta refresh' => ['<meta http-equiv=refresh content=0;url=javascript:alert(1)>'],
            'template tag' => ['<template><script>alert(1)</script></template>'],
        ];
    }

    private function persistWithUserAgent(string $userAgent): ?SecurityDataAudit
    {
        $request = Request::create('/profile/update', 'POST', ['name' => 'ok'], [], [], [
            'HTTP_USER_AGENT' => $userAgent,
        ]);
        $this->app->instance('request', $request);

        return $this->persistModel();
    }

    private function persistWithBody(array $body): ?SecurityDataAudit
    {
        $request = Request::create('/profile/update', 'POST', $body, [], [], [
            'HTTP_USER_AGENT' => 'Mozilla/5.0',
        ]);
        $this->app->instance('request', $request);

        return $this->persistModel();
    }

    private function persistModel(): ?SecurityDataAudit
    {
        $model = AuditXssProbeModel::create(['name' => 'probe']);

        return SecurityDataAudit::query()
            ->where('auditable_type', AuditXssProbeModel::class)
            ->where('auditable_id', (string) $model->getKey())
            ->where('event', 'created')
            ->first();
    }

    /**
     * Markup that could execute in an HTML/JS sink must be gone outright:
     * defanging removes the tag brackets, it does not merely escape them.
     */
    private function assertNoExecutableMarkup(string $haystack): void
    {
        $lower = strtolower($haystack);
        foreach (['<script', '<svg', '<iframe', '<img', '<object', '<embed', '<style', '<meta', '<link', '<base', 'javascript:', 'vbscript:'] as $marker) {
            $this->assertStringNotContainsString($marker, $lower, "Executable marker persisted: {$marker} in {$haystack}");
        }
    }
}
