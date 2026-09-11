<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature;

use Illuminate\Support\Facades\Cache;
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

        $response = $this->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])->get('/security-defense');

        $response->assertStatus(200);
        $response->assertSee('credential stuffing');
        $response->assertSee('203.0.113.55');
        $response->assertSee('Release IP', false);
        $response->assertDontSee('&#128640;');
        $response->assertSee('Inspect (2)');
        $response->assertSee('Attack Vector Prevalence');
        $response->assertSee('@custom-variant dark');
        $response->assertSee('text/tailwindcss');
    }

    public function test_epistemic_page_renders_with_config(): void
    {
        $this->app['env'] = 'local';
        config()->set('security-defense.epistemic.enabled', false);

        // Seed cache with a realistic last_analysis payload (serialised belief shapes).
        Cache::put((string) config('security-defense.cache_prefix', 'security_defense:') . 'epistemic:last_analysis', [
            'risk' => 0.62,
            'confidence' => 0.41,
            'hypotheses' => [
                [
                    'hypothesis' => 'credential_stuffing',
                    'confidence' => 0.41,
                    'risk' => 0.62,
                    'supporting' => ['login_failed', 'new_location'],
                    'contradicting' => ['trusted_device'],
                    'action' => 'challenge',
                ],
            ],
            'evidence_feed' => [
                [
                    'type' => 'login_failed',
                    'source' => 'auth:login',
                    'timestamp' => '2026-09-10T10:00:00+00:00',
                    'reliability' => 0.9,
                ],
            ],
        ], 60);

        $response = $this->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
            ->get('/security-defense/epistemic');

        $response->assertStatus(200);
        $response->assertSee('Threat reasoning dashboard', false);
        $response->assertSee('credential_stuffing', false);
        $response->assertSee('challenge', false);
        $response->assertSee('login_failed', false);
        $response->assertSee('Engine disabled', false);
        $response->assertSee('NoopResponseAdapter', false);
        $response->assertDontSee('&#128640;');
    }

    public function test_epistemic_feedback_requires_valid_outcome_and_hypothesis(): void
    {
        $this->app['env'] = 'local';
        config()->set('security-defense.epistemic.enabled', true);
        $this->withoutMiddleware();

        $response = $this->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
            ->post('/security-defense/epistemic/feedback', [
                '_token' => csrf_token(),
                'hypothesis' => 'credential_stuffing',
                'outcome' => 'confirmed_attack',
            ]);

        $response->assertStatus(302); // redirect back
        $response->assertSessionHas('status_message');
    }

    public function test_epistemic_feedback_rejects_unknown_hypothesis(): void
    {
        $this->app['env'] = 'local';
        config()->set('security-defense.epistemic.enabled', true);
        $this->withoutMiddleware();

        $response = $this->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
            ->post('/security-defense/epistemic/feedback', [
                '_token' => csrf_token(),
                'hypothesis' => 'not_a_real_hypothesis',
                'outcome' => 'confirmed_attack',
            ]);

        $response->assertSessionHasErrors('hypothesis');
    }
}
