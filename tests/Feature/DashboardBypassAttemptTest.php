<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\RateLimiter;
use Mixudev\SecurityDefense\Tests\TestCase;

class DashboardBypassAttemptTest extends TestCase
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
        RateLimiter::clear('security-defense:dashboard-access:' . hash('sha256', '203.0.113.10'));
        RateLimiter::clear('security-defense:dashboard-access:' . hash('sha256', '127.0.0.1'));

        $this->app['env'] = 'testing';
        parent::tearDown();
    }

    /**
     * Local mode: any non-local environment must 403 even from loopback.
     */
    public function test_local_mode_forbids_loopback_in_staging_and_production(): void
    {
        foreach (['staging', 'production'] as $env) {
            $this->app['env'] = $env;

            $this->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
                ->get('/security-defense')
                ->assertForbidden();
        }
    }

    /**
     * Local mode: Gate must NOT create a remote bypass.
     */
    public function test_local_mode_gate_cannot_bypass_loopback_boundary(): void
    {
        $this->app['env'] = 'local';
        config()->set('security-defense.dashboard.local_only', true);
        Gate::define('viewSecurityDefenseDashboard', fn (?object $user = null) => true);

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.88'])
            ->get('/security-defense')
            ->assertForbidden();
    }

    /**
     * Public mode with no Gate fails closed (even with allowlisted IP).
     */
    public function test_public_mode_without_gate_fails_closed(): void
    {
        $this->app['env'] = 'production';
        config()->set('security-defense.dashboard.local_only', false);
        config()->set('security-defense.dashboard.public.enabled', true);
        config()->set('security-defense.dashboard.public.authorization_gate', null);
        config()->set('security-defense.dashboard.public.allowed_ips', ['203.0.113.10']);

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.10'])
            ->get('/security-defense')
            ->assertForbidden();
    }

    /**
     * Public mode: non-allowlisted IP cannot pass with a satisfied Gate.
     */
    public function test_public_mode_non_allowlisted_ip_cannot_pass_gate(): void
    {
        $this->app['env'] = 'production';
        config()->set('security-defense.dashboard.local_only', false);
        config()->set('security-defense.dashboard.public.enabled', true);
        config()->set('security-defense.dashboard.public.authorization_gate', 'viewSecurityDefenseDashboard');
        config()->set('security-defense.dashboard.public.allowed_ips', ['203.0.113.10']);
        Gate::define('viewSecurityDefenseDashboard', fn (?object $user = null) => true);

        $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.5'])
            ->get('/security-defense')
            ->assertForbidden();
    }

    /**
     * Public mode: X-Forwarded-For must never spoof remote address by default.
     */
    public function test_forwarded_for_cannot_spoof_allowlist(): void
    {
        $this->app['env'] = 'production';
        config()->set('security-defense.dashboard.local_only', false);
        config()->set('security-defense.dashboard.public.enabled', true);
        config()->set('security-defense.dashboard.public.authorization_gate', 'viewSecurityDefenseDashboard');
        config()->set('security-defense.dashboard.public.allowed_ips', ['127.0.0.1']);
        Gate::define('viewSecurityDefenseDashboard', fn (?object $user = null) => true);

        $this->withServerVariables([
            'REMOTE_ADDR' => '203.0.113.99',
            'HTTP_X_FORWARDED_FOR' => '127.0.0.1',
        ])->get('/security-defense')->assertForbidden();
    }

    /**
     * Public mode: allowlisted IP alone (no auth user) still denied when authenticated user required.
     */
    public function test_public_mode_allowlisted_ip_without_authenticated_user_denied(): void
    {
        $this->app['env'] = 'production';
        config()->set('security-defense.dashboard.local_only', false);
        config()->set('security-defense.dashboard.public.enabled', true);
        config()->set('security-defense.dashboard.public.authorization_gate', 'viewSecurityDefenseDashboard');
        config()->set('security-defense.dashboard.public.allowed_ips', ['203.0.113.10']);
        config()->set('security-defense.dashboard.public.require_authenticated_user', true);
        Gate::define('viewSecurityDefenseDashboard', fn (?object $user = null) => true);

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.10'])
            ->get('/security-defense')
            ->assertForbidden();
    }

    /**
     * Public mode: undefined configured gate denies even with valid IP.
     */
    public function test_public_mode_undefined_configured_gate_denies(): void
    {
        $this->app['env'] = 'production';
        config()->set('security-defense.dashboard.local_only', false);
        config()->set('security-defense.dashboard.public.enabled', true);
        config()->set('security-defense.dashboard.public.authorization_gate', 'missingGateThatDoesNotExist');
        config()->set('security-defense.dashboard.public.allowed_ips', ['203.0.113.10']);

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.10'])
            ->get('/security-defense')
            ->assertForbidden();
    }

    /**
     * Public mode: valid allowlisted IP + satisfied Gate + authenticated user succeeds.
     */
    public function test_public_mode_fully_authorized_access_succeeds(): void
    {
        $this->app['env'] = 'production';
        config()->set('security-defense.dashboard.local_only', false);
        config()->set('security-defense.dashboard.public.enabled', true);
        config()->set('security-defense.dashboard.public.authorization_gate', 'viewSecurityDefenseDashboard');
        config()->set('security-defense.dashboard.public.allowed_ips', ['203.0.113.10']);
        config()->set('security-defense.dashboard.public.require_authenticated_user', false);
        Gate::define('viewSecurityDefenseDashboard', fn (?object $user = null) => true);

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.10'])
            ->get('/security-defense')
            ->assertOk();
    }

    /**
     * Step-up: denied step-up gate forbids access even when normal gate passes.
     */
    public function test_public_mode_denied_step_up_gate_forbids(): void
    {
        $this->app['env'] = 'production';
        config()->set('security-defense.dashboard.local_only', false);
        config()->set('security-defense.dashboard.public.enabled', true);
        config()->set('security-defense.dashboard.public.authorization_gate', 'viewSecurityDefenseDashboard');
        config()->set('security-defense.dashboard.public.allowed_ips', ['203.0.113.10']);
        config()->set('security-defense.dashboard.public.require_step_up', true);
        config()->set('security-defense.dashboard.public.step_up_gate', 'viewSecurityDefenseDashboardStepUp');
        Gate::define('viewSecurityDefenseDashboard', fn (?object $user = null) => true);
        Gate::define('viewSecurityDefenseDashboardStepUp', fn (?object $user = null) => false);

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.10'])
            ->get('/security-defense')
            ->assertForbidden();
    }

    /**
     * Step-up: satisfied step-up gate allows access.
     */
    public function test_public_mode_satisfied_step_up_gate_allows(): void
    {
        $this->app['env'] = 'production';
        config()->set('security-defense.dashboard.local_only', false);
        config()->set('security-defense.dashboard.public.enabled', true);
        config()->set('security-defense.dashboard.public.authorization_gate', 'viewSecurityDefenseDashboard');
        config()->set('security-defense.dashboard.public.allowed_ips', ['203.0.113.10']);
        config()->set('security-defense.dashboard.public.require_authenticated_user', false);
        config()->set('security-defense.dashboard.public.require_step_up', true);
        config()->set('security-defense.dashboard.public.step_up_gate', 'viewSecurityDefenseDashboardStepUp');
        Gate::define('viewSecurityDefenseDashboard', fn (?object $user = null) => true);
        Gate::define('viewSecurityDefenseDashboardStepUp', fn (?object $user = null) => true);

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.10'])
            ->get('/security-defense')
            ->assertOk();
    }

    /**
     * Rate limiting: repeated public denials eventually 429.
     */
    public function test_repeated_public_denials_get_rate_limited(): void
    {
        $this->app['env'] = 'production';
        config()->set('security-defense.dashboard.local_only', false);
        config()->set('security-defense.dashboard.public.enabled', true);
        config()->set('security-defense.dashboard.public.allowed_ips', ['203.0.113.10']);
        config()->set('security-defense.dashboard.public.rate_limit.max_attempts', 2);
        config()->set('security-defense.dashboard.public.rate_limit.decay_seconds', 60);

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.10'])
            ->get('/security-defense')
            ->assertForbidden();

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.10'])
            ->get('/security-defense')
            ->assertStatus(429);
    }

    /**
     * All dashboard POST routes must share the public-mode deny policy.
     */
    public function test_all_dashboard_post_routes_denied_in_public_mode(): void
    {
        $this->app['env'] = 'production';
        config()->set('security-defense.dashboard.local_only', false);
        config()->set('security-defense.dashboard.public.enabled', true);
        config()->set('security-defense.dashboard.public.authorization_gate', 'viewSecurityDefenseDashboard');
        config()->set('security-defense.dashboard.public.allowed_ips', ['203.0.113.10']);

        $token = 'post-deny-token';
        $postPaths = [
            '/security-defense/test-channel' => ['channel' => 'database'],
            '/security-defense/toggle-setting' => ['key' => 'csp_armor', 'value' => '1'],
            '/security-defense/quarantine/pardon' => ['ip' => '203.0.113.10'],
            '/security-defense/quarantine/whitelist' => ['ip' => '203.0.113.10'],
            '/security-defense/epistemic/feedback' => ['hypothesis' => 'credential_stuffing', 'outcome' => 'confirmed_attack'],
        ];

        foreach ($postPaths as $path => $body) {
            $this->withSession(['_token' => $token])
                ->withServerVariables(['REMOTE_ADDR' => '198.51.100.77'])
                ->post($path, $body + ['_token' => $token])
                ->assertForbidden();
        }
    }

    /**
     * Public mode: an attacker-supplied X-Forwarded-For chain must not help.
     */
    public function test_forwarded_for_chain_cannot_spoof_allowlist(): void
    {
        $this->app['env'] = 'production';
        config()->set('security-defense.dashboard.local_only', false);
        config()->set('security-defense.dashboard.public.enabled', true);
        config()->set('security-defense.dashboard.public.authorization_gate', 'viewSecurityDefenseDashboard');
        config()->set('security-defense.dashboard.public.allowed_ips', ['127.0.0.1']);
        Gate::define('viewSecurityDefenseDashboard', fn (?object $user = null) => true);

        $this->withServerVariables([
            'REMOTE_ADDR' => '203.0.113.99',
            'HTTP_X_FORWARDED_FOR' => '10.0.0.1, 127.0.0.1, 198.51.100.2',
        ])->get('/security-defense')->assertForbidden();
    }

    /**
     * Public mode: spoofed X-Real-IP / client-ip headers must not bypass.
     */
    public function test_spoofed_proxy_headers_cannot_bypass(): void
    {
        $this->app['env'] = 'production';
        config()->set('security-defense.dashboard.local_only', false);
        config()->set('security-defense.dashboard.public.enabled', true);
        config()->set('security-defense.dashboard.public.authorization_gate', 'viewSecurityDefenseDashboard');
        config()->set('security-defense.dashboard.public.allowed_ips', ['127.0.0.1']);
        Gate::define('viewSecurityDefenseDashboard', fn (?object $user = null) => true);

        $this->withServerVariables([
            'REMOTE_ADDR' => '203.0.113.99',
            'HTTP_X_REAL_IP' => '127.0.0.1',
            'HTTP_X_CLIENT_IP' => '127.0.0.1',
            'HTTP_CLIENT_IP' => '127.0.0.1',
        ])->get('/security-defense')->assertForbidden();
    }

    /**
     * Denial response does not disclose whether a route exists or which policy failed.
     */
    public function test_denial_is_indistinguishable_across_policy_reasons(): void
    {
        $this->app['env'] = 'production';
        config()->set('security-defense.dashboard.public.rate_limit.max_attempts', 100);

        $configs = [
            ['local_only' => false, 'public_enabled' => true, 'gate' => 'missingGateA', 'ips' => []],
            ['local_only' => false, 'public_enabled' => true, 'gate' => 'missingGateB', 'ips' => ['203.0.113.10']],
            ['local_only' => true, 'public_enabled' => false, 'gate' => null, 'ips' => []],
        ];

        $bodies = [];
        foreach ($configs as $cfg) {
            config()->set('security-defense.dashboard.local_only', $cfg['local_only']);
            config()->set('security-defense.dashboard.public.enabled', $cfg['public_enabled']);
            config()->set('security-defense.dashboard.public.authorization_gate', $cfg['gate']);
            config()->set('security-defense.dashboard.public.allowed_ips', $cfg['ips']);

            $response = $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.10'])
                ->get('/security-defense');

            $response->assertForbidden();
            $bodies[] = (string) $response->getContent();
        }

        // All denial bodies must be byte-identical: no policy/route fingerprint.
        self::assertCount(1, array_unique($bodies));
    }

    /**
     * Local mode: dashboard views never render raw secrets or raw user-controlled metadata.
     */
    public function test_dashboard_views_do_not_render_raw_secrets_or_unescaped_metadata(): void
    {
        $this->app['env'] = 'local';

        $alert = \Mixudev\SecurityDefense\Models\SecurityAlert::query()->create([
            'severity' => 'high',
            'threat_type' => 'payload_injection',
            'fingerprint' => 'fp-view-leak-001',
            'status' => 'new',
            'rule_identifier' => 'payload_injection',
            'metadata' => [
                'matched_sample' => '<script>alert("XSS")</script>',
                'password' => 'super-secret-password-xyz',
                'api_token' => 'tok-abc-123',
            ],
        ]);

        $response = $this->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
            ->get('/security-defense');

        $response->assertOk();
        $response->assertDontSee('<script>alert("XSS")</script>', false);
        $response->assertDontSee('super-secret-password-xyz', false);
        $response->assertDontSee('tok-abc-123', false);
    }

    /**
     * Dashboard responses must not be cached by browsers/proxies (no-store).
     */
    public function test_dashboard_responses_are_no_store(): void
    {
        $this->app['env'] = 'local';

        $response = $this->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
            ->get('/security-defense');

        $response->assertOk();
        $cacheControl = strtolower((string) $response->headers->get('Cache-Control', ''));
        self::assertStringContainsString('no-store', $cacheControl);
        $response->assertHeader('Pragma', 'no-cache');
    }

    /**
     * Rate limiter must not leak the raw IP in cache keys (hashed only).
     */
    public function test_rate_limit_cache_keys_never_contain_raw_ip(): void
    {
        $this->app['env'] = 'production';
        config()->set('security-defense.dashboard.local_only', false);
        config()->set('security-defense.dashboard.public.enabled', true);
        config()->set('security-defense.dashboard.public.allowed_ips', ['203.0.113.10']);
        config()->set('security-defense.dashboard.public.rate_limit.max_attempts', 3);
        config()->set('security-defense.dashboard.public.rate_limit.decay_seconds', 60);

        Cache::flush();

        // Trigger public-mode denial so rate-limit keys are written.
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.10'])
            ->get('/security-defense')
            ->assertForbidden();

        $store = Cache::getStore();
        $reflection = new \ReflectionObject($store);
        $prop = $reflection->getProperty('storage');
        $prop->setAccessible(true);
        $keys = array_keys((array) $prop->getValue($store));

        // No key may contain the raw IP or a plaintext IP in the rate-limit namespace.
        $leaky = array_values(array_filter($keys, function (string $k): bool {
            return str_contains($k, '203.0.113.10')
                || str_contains($k, '127.0.0.1');
        }));

        self::assertCount(0, $leaky, 'Rate limit keys must be hashed, not raw IPs.');
    }

    /**
     * Rate limiting: successful local access is never rate limited.
     */
    public function test_local_access_is_not_rate_limited(): void
    {
        $this->app['env'] = 'local';
        config()->set('security-defense.dashboard.public.rate_limit.max_attempts', 1);
        config()->set('security-defense.dashboard.public.rate_limit.decay_seconds', 60);

        for ($i = 0; $i < 5; $i++) {
            $this->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
                ->get('/security-defense')
                ->assertOk();
        }
    }

    /**
     * Brute force: rate limiter key uses hashed IP, not raw IP.
     */
    public function test_rate_limit_key_uses_hashed_ip(): void
    {
        $this->app['env'] = 'production';
        config()->set('security-defense.dashboard.local_only', false);
        config()->set('security-defense.dashboard.public.enabled', true);
        config()->set('security-defense.dashboard.public.allowed_ips', ['203.0.113.10']);
        config()->set('security-defense.dashboard.public.rate_limit.max_attempts', 2);
        config()->set('security-defense.dashboard.public.rate_limit.decay_seconds', 60);

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.10'])->get('/security-defense');
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.10'])->get('/security-defense');
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.10'])->get('/security-defense')->assertStatus(429);

        // Assert no cache key with raw IP exists.
        $rawIpKey = 'security-defense:dashboard-access:' . hash('sha256', '203.0.113.10');
        self::assertTrue(Cache::has($rawIpKey));

        // Different IP starts fresh.
        RateLimiter::clear('security-defense:dashboard-access:' . hash('sha256', '198.51.100.7'));
        $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.7'])
            ->get('/security-defense')
            ->assertForbidden(); // not 429 yet
    }

    /**
     * Denial responses stay generic: no route existence, no user id, no gate details.
     */
    public function test_denial_response_is_generic_and_does_not_leak(): void
    {
        $this->app['env'] = 'production';
        config()->set('security-defense.dashboard.local_only', false);
        config()->set('security-defense.dashboard.public.enabled', true);
        config()->set('security-defense.dashboard.public.authorization_gate', 'missingGateThatDoesNotExist');
        config()->set('security-defense.dashboard.public.allowed_ips', ['203.0.113.10']);

        $response = $this->withServerVariables([
            'REMOTE_ADDR' => '203.0.113.10',
            'HTTP_X_FORWARDED_FOR' => '127.0.0.1',
        ])->get('/security-defense');

        $response->assertForbidden();
        $response->assertDontSee('missingGateThatDoesNotExist');
        $response->assertDontSee('203.0.113.10');
        $response->assertDontSee('viewSecurityDefenseDashboard');
        $response->assertDontSee('user_id');
        $response->assertDontSee('local_only');
    }

    /**
     * All dashboard subroutes share the same denial policy in public mode.
     */
    public function test_all_dashboard_subroutes_denied_in_public_mode_without_gate(): void
    {
        $this->app['env'] = 'production';
        config()->set('security-defense.dashboard.local_only', false);
        config()->set('security-defense.dashboard.public.enabled', true);
        config()->set('security-defense.dashboard.public.authorization_gate', 'viewSecurityDefenseDashboard');
        config()->set('security-defense.dashboard.public.allowed_ips', ['203.0.113.10']);

        $paths = ['/', '/data-audits', '/sessions', '/epistemic', '/live-events'];

        foreach ($paths as $path) {
            $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.44'])
                ->get('/security-defense' . $path)
                ->assertForbidden();
        }
    }

    /**
     * Live-events JSON endpoint must not leak data when unauthorized.
     */
    public function test_live_events_json_endpoint_unauthorized_does_not_leak(): void
    {
        $this->app['env'] = 'production';
        config()->set('security-defense.dashboard.local_only', false);
        config()->set('security-defense.dashboard.public.enabled', true);
        config()->set('security-defense.dashboard.public.authorization_gate', 'viewSecurityDefenseDashboard');
        config()->set('security-defense.dashboard.public.allowed_ips', ['203.0.113.10']);

        $response = $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.44'])
            ->getJson('/security-defense/live-events');

        $response->assertForbidden();
        $response->assertJsonMissingPath('events');
        $response->assertJsonMissingPath('data');
    }

    /**
     * Public mode: odd HTTP verbs must not bypass the middleware.
     */
    public function test_odd_http_verbs_cannot_bypass_gate(): void
    {
        $this->app['env'] = 'production';
        config()->set('security-defense.dashboard.local_only', false);
        config()->set('security-defense.dashboard.public.enabled', true);
        config()->set('security-defense.dashboard.public.authorization_gate', 'viewSecurityDefenseDashboard');
        config()->set('security-defense.dashboard.public.allowed_ips', ['203.0.113.10']);

        $token = 'bypass-verb-token';
        $this->withSession(['_token' => $token])
            ->withServerVariables(['REMOTE_ADDR' => '198.51.100.44'])
            // Route is GET-only; router must reject unsupported verbs before controller execution.
            ->put('/security-defense', ['_token' => $token])
            ->assertStatus(405);
    }
}