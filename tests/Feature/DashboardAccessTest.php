<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature;

use Illuminate\Support\Facades\Gate;
use Mixudev\SecurityDefense\Models\SecurityAlert;
use Mixudev\SecurityDefense\Tests\TestCase;

class DashboardAccessTest extends TestCase
{
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app['config']->set('app.key', 'base64:7VzK9gG2e+x8UfXoN9uC7x/2j6yD8Hw0Z1A2B3C4D5E=');
        $app['config']->set('security-defense.dashboard.enabled', true);
        $app['config']->set('security-defense.dashboard.local_only', true);
        $app['config']->set('security-defense.dashboard.allowed_ips', ['127.0.0.1', '::1']);
    }

    protected function tearDown(): void
    {
        // Restore environment to testing so teardown migration rollbacks don't prompt in production
        $this->app['env'] = 'testing';

        parent::tearDown();
    }

    public function test_dashboard_is_accessible_in_local_environment_with_localhost_ip(): void
    {
        $this->app['env'] = 'local';

        $response = $this->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
            ->get('/security-defense');

        $response->assertStatus(200);
        $response->assertSee('Laravel Security Defense');
        $response->assertSee('Strict Local Mode Active');
    }

    public function test_dashboard_is_forbidden_in_production_environment(): void
    {
        $this->app['env'] = 'production';

        $response = $this->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
            ->get('/security-defense');

        $response->assertStatus(403);
    }

    public function test_dashboard_is_forbidden_from_unauthorized_external_ip(): void
    {
        $this->app['env'] = 'local';

        $response = $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.88'])
            ->get('/security-defense');

        $response->assertStatus(403);
    }

    public function test_dashboard_returns_404_when_disabled(): void
    {
        config()->set('security-defense.dashboard.enabled', false);

        $response = $this->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
            ->get('/security-defense');

        $response->assertStatus(404);
    }

    public function test_anonymous_remote_access_is_forbidden_when_dashboard_is_exposed(): void
    {
        $this->app['env'] = 'production';
        config()->set('security-defense.dashboard.local_only', false);

        $response = $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.88'])
            ->get('/security-defense');

        $response->assertStatus(403);
        $response->assertSee('Forbidden.');
    }

    public function test_dashboard_probe_returns_generic_client_error(): void
    {
        $this->app['env'] = 'local';
        $this->mock(\Mixudev\SecurityDefense\Services\ChannelTestService::class)
            ->shouldReceive('testChannel')->once()->andThrow(new \RuntimeException('secret provider failure'));

        $token = 'test-valid-csrf-token-error';
        $response = $this->withSession(['_token' => $token])
            ->withHeaders(['X-CSRF-TOKEN' => $token, 'Accept' => 'application/json'])
            ->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
            ->post('/security-defense/test-channel', [
                'channel' => 'database',
                '_token' => $token,
            ]);

        $response->assertStatus(500);
        $response->assertJsonPath('message', 'Channel probe failed. Please check server logs.');
        $response->assertJsonMissing(['message' => 'secret provider failure']);
    }

    public function test_dashboard_allows_access_if_custom_gate_is_satisfied(): void
    {
        $this->app['env'] = 'production';

        Gate::define('viewSecurityDefenseDashboard', fn (?object $user = null) => true);

        $response = $this->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
            ->get('/security-defense');

        $response->assertStatus(200);
    }

    public function test_test_channel_endpoint_enforces_csrf_protection(): void
    {
        $this->app['env'] = 'local';

        // Direct POST without valid CSRF header/token gets rejected with 419 (Strict Security)
        $response = $this->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
            ->post('/security-defense/test-channel', [
                'channel' => 'database',
            ]);

        $response->assertStatus(419);
    }

    public function test_test_channel_endpoint_executes_probe_and_returns_json(): void
    {
        $this->app['env'] = 'local';

        $token = 'test-valid-csrf-token-12345';

        $response = $this->withSession(['_token' => $token])
            ->withHeaders(['X-CSRF-TOKEN' => $token, 'Accept' => 'application/json'])
            ->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
            ->post('/security-defense/test-channel', [
                'channel' => 'database',
                '_token' => $token,
            ]);

        $response->assertStatus(200);
        $response->assertJsonPath('success', true);
        $response->assertJsonStructure([
            'success',
            'results' => [
                'database' => ['channel', 'success', 'enabled', 'configured', 'message'],
            ],
        ]);
    }

    public function test_alert_can_be_acknowledged_and_resolved_from_dashboard(): void
    {
        $this->app['env'] = 'local';

        $alert = SecurityAlert::query()->create([
            'severity' => 'high',
            'threat_type' => 'brute_force',
            'fingerprint' => 'fp-action-test-456',
            'status' => 'new',
            'rule_identifier' => 'brute_force',
            'metadata' => ['target' => 'admin@app.test'],
        ]);

        $this->assertSame('new', $alert->status);

        $token = 'test-valid-csrf-token-789';

        // Acknowledge
        $ackResponse = $this->withSession(['_token' => $token])
            ->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
            ->post("/security-defense/alerts/{$alert->id}/acknowledge", [
                '_token' => $token,
            ]);

        $ackResponse->assertRedirect();
        $alert->refresh();
        $this->assertSame('acknowledged', $alert->status);

        // Resolve
        $resolveResponse = $this->withSession(['_token' => $token])
            ->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
            ->post("/security-defense/alerts/{$alert->id}/resolve", [
                '_token' => $token,
            ]);

        $resolveResponse->assertRedirect();
        $alert->refresh();
        $this->assertSame('resolved', $alert->status);
    }
}
