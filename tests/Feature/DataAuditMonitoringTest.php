<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Schema;
use Mixudev\SecurityDefense\Models\SecurityDataAudit;
use Mixudev\SecurityDefense\Support\Traits\HasSecurityAudit;
use Mixudev\SecurityDefense\Tests\TestCase;

class TestAuditableModel extends Model
{
    use HasSecurityAudit;

    protected $table = 'test_auditable_models';
    protected $guarded = [];
}

class DataAuditMonitoringTest extends TestCase
{
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app['config']->set('app.key', 'base64:7VzK9gG2e+x8UfXoN9uC7x/2j6yD8Hw0Z1A2B3C4D5E=');
        $app['config']->set('security-defense.dashboard.enabled', true);
        $app['config']->set('security-defense.dashboard.local_only', true);
        $app['config']->set('security-defense.dashboard.allowed_ips', ['127.0.0.1', '::1']);
    }

    protected function setUp(): void
    {
        parent::setUp();

        Schema::create('test_auditable_models', function (Blueprint $table) {
            $table->id();
            $table->string('name');
            $table->string('email');
            $table->string('password')->nullable();
            $table->boolean('is_admin')->default(false);
            $table->timestamps();
        });
    }

    public function test_it_records_model_creation_with_sanitized_passwords(): void
    {
        $model = TestAuditableModel::create([
            'name' => 'Alice Doe',
            'email' => 'alice@example.com',
            'password' => 'supersecret123',
            'is_admin' => false,
        ]);

        $audit = SecurityDataAudit::query()
            ->where('auditable_type', TestAuditableModel::class)
            ->where('auditable_id', (string) $model->id)
            ->where('event', 'created')
            ->first();

        $this->assertNotNull($audit);
        $this->assertSame('created', $audit->event);
        $this->assertArrayHasKey('name', $audit->new_values);
        $this->assertSame('Alice Doe', $audit->new_values['name']);

        // Password MUST be redacted
        $this->assertSame('******** [REDACTED]', $audit->new_values['password']);
        $this->assertFalse($audit->is_tampered);
    }

    public function test_it_records_model_updates_with_diff(): void
    {
        $model = TestAuditableModel::create([
            'name' => 'Bob Initial',
            'email' => 'bob@example.com',
            'is_admin' => false,
        ]);

        $model->update([
            'name' => 'Bob Updated',
        ]);

        $audit = SecurityDataAudit::query()
            ->where('auditable_type', TestAuditableModel::class)
            ->where('auditable_id', (string) $model->id)
            ->where('event', 'updated')
            ->first();

        $this->assertNotNull($audit);
        $this->assertSame(['name'], $audit->modified_fields);
        $this->assertSame('Bob Initial', $audit->old_values['name']);
        $this->assertSame('Bob Updated', $audit->new_values['name']);
    }

    public function test_it_detects_burp_suite_parameter_tampering_on_sensitive_fields(): void
    {
        // Mock an HTTP request injecting is_admin parameter
        $request = Request::create('/profile/update', 'POST', [
            'name' => 'Hacker Name',
            'is_admin' => 1,
        ]);
        $this->app->instance('request', $request);

        $model = TestAuditableModel::create([
            'name' => 'Normal User',
            'email' => 'user@example.com',
            'is_admin' => false,
        ]);

        $model->update([
            'name' => 'Hacker Name',
            'is_admin' => true,
        ]);

        $audit = SecurityDataAudit::query()
            ->where('auditable_type', TestAuditableModel::class)
            ->where('auditable_id', (string) $model->id)
            ->where('event', 'updated')
            ->first();

        $this->assertNotNull($audit);
        $this->assertTrue($audit->is_tampered);
        $this->assertNotEmpty($audit->tamper_reasons);
        $this->assertStringContainsString('is_admin', $audit->tamper_reasons[0]);
    }

    public function test_dashboard_routes_and_audits_view_render_successfully(): void
    {
        $this->app['env'] = 'local';

        $response = $this->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
            ->get('/security-defense/data-audits');
        $response->assertStatus(200);
        $response->assertSee('Database Mutation Log');

        $sessionResponse = $this->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
            ->get('/security-defense/sessions');
        $sessionResponse->assertStatus(200);
        $sessionResponse->assertSee('Session Intelligence Telemetry');
    }
}
