<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature;

use Mixudev\SecurityDefense\Models\SecurityAlert;
use Mixudev\SecurityDefense\Models\SecurityQuarantine;
use Mixudev\SecurityDefense\Tests\TestCase;

class DashboardRenderDataTest extends TestCase
{
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);
        $app['config']->set('app.key', 'base64:7VzK9gG2e+x8UfXoN9uC7x/2j6yD8Hw0Z1A2B3C4D5E=');
        $app['config']->set('security-defense.dashboard.enabled', true);
        $app['config']->set('security-defense.dashboard.local_only', true);
        $app['config']->set('security-defense.dashboard.allowed_ips', ['127.0.0.1', '::1']);
    }

    public function test_dashboard_renders_with_populated_data(): void
    {
        $this->app['env'] = 'local';

        SecurityAlert::query()->create([
            'severity' => 'critical',
            'threat_type' => 'credential_stuffing',
            'fingerprint' => 'fp-populated-111',
            'status' => 'new',
            'rule_identifier' => 'credential_stuffing',
            'metadata' => ['target' => 'victim@example.com', 'ip' => '203.0.113.9'],
        ]);
        SecurityAlert::query()->create([
            'severity' => 'high',
            'threat_type' => 'payload_injection',
            'fingerprint' => 'fp-populated-222',
            'status' => 'acknowledged',
            'rule_identifier' => 'payload_injection',
            'metadata' => ['path' => '/prod/.env', 'ip' => '203.0.113.10'],
        ]);

        SecurityQuarantine::query()->create([
            'ip' => '203.0.113.55',
            'jailed_at' => now(),
            'expires_at' => now()->addMinutes(10),
            'reason' => 'Auto-quarantined due to payload injection attack',
        ]);

        $response = $this->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
            ->get('/security-defense');

        $response->assertStatus(200);
        $response->assertSee('credential stuffing'); // escaped threat type rendered in distribution
        $response->assertSee('203.0.113.55'); // quarantine IP
        $response->assertSee('Release IP', false); // quarantine action
        $response->assertDontSee('&#128640;'); // no emoji leaks
        $response->assertSee('Inspect (2)'); // telemetry count for 2 metadata keys
        $response->assertSee('Attack Vector Prevalence'); // distribution rendered
    }
}
