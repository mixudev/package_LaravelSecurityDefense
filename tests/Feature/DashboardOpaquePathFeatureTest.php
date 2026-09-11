<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature;

use Mixudev\SecurityDefense\Support\OpaqueRouteAliases;
use Mixudev\SecurityDefense\Tests\TestCase;

class DashboardOpaquePathFeatureTest extends TestCase
{
    private const TOKEN = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);
        $app['config']->set('app.key', 'base64:' . base64_encode(random_bytes(32)));
        $app['env'] = 'local';
        $app['config']->set('security-defense.dashboard.opaque_path.enabled', true);
    }

    protected function tearDown(): void
    {
        if (isset($this->app)) {
            $this->app['env'] = 'testing';
        }
        parent::tearDown();
    }

    public function test_predictable_route_is_secure_gate_when_opaque_enabled(): void
    {
        $this->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
            ->get('/security-defense')
            ->assertOk()
            ->assertDontSee(self::TOKEN);
    }

    public function test_valid_opaque_path_reaches_dashboard_locally(): void
    {
        $this->app['session']->setId('fixed-test-session');
        $sessionPath = app(\Mixudev\SecurityDefense\Support\DashboardCapability::class)->sessionPath('fixed-test-session');

        $this->withSession([
            'security-defense.dashboard-authorized' => true,
            'security-defense.dashboard-session-path' => $sessionPath,
            '_token' => 't',
        ])
            ->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
            ->get('/' . $sessionPath)
            ->assertOk();
    }

    public function test_unknown_opaque_path_returns_404(): void
    {
        $wrong = 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB';

        $this->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
            ->get('/' . $wrong)
            ->assertNotFound();
    }

    public function test_query_and_fragment_tokens_never_authorize(): void
    {
        // Opaque mode: predictable route is the gate, NOT authorizing by token.
        $this->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
            ->get('/security-defense?token=' . self::TOKEN)
            ->assertOk()
            ->assertDontSee(self::TOKEN);

        // A query token on the opaque path itself must remain irrelevant.
        $this->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
            ->get('/' . self::TOKEN . '?token=' . self::TOKEN)
            ->assertNotFound();
    }

    public function test_opaque_path_does_not_bypass_public_gateway(): void
    {
        $this->app['env'] = 'production';
        config()->set('security-defense.dashboard.local_only', false);
        config()->set('security-defense.dashboard.public.enabled', false);

        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.7'])
            ->get('/' . self::TOKEN)
            ->assertNotFound();
    }

    public function test_all_dashboard_subroutes_share_opaque_prefix_via_aliases(): void
    {
        $this->app['session']->setId('fixed-test-session');
        $sessionPath = app(\Mixudev\SecurityDefense\Support\DashboardCapability::class)->sessionPath('fixed-test-session');
        $session = [
            'security-defense.dashboard-authorized' => true,
            'security-defense.dashboard-session-path' => $sessionPath,
        ];

        foreach ([
            OpaqueRouteAliases::path('security-defense.data-audits'),
            OpaqueRouteAliases::path('security-defense.sessions'),
            OpaqueRouteAliases::path('security-defense.epistemic'),
            OpaqueRouteAliases::path('security-defense.live-events'),
        ] as $subpath) {
            $this->withSession($session)
                ->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
                ->get('/' . $sessionPath . '/' . $subpath)
                ->assertOk();
        }
    }

    public function test_legacy_literal_suffix_has_no_route_in_opaque_mode(): void
    {
        foreach (['/data-audits', '/sessions', '/epistemic', '/live-events'] as $subpath) {
            $this->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
                ->get('/' . self::TOKEN . $subpath)
                ->assertNotFound();
        }
    }

    public function test_token_is_not_part_of_runtime_config_values(): void
    {
        self::assertArrayNotHasKey('token', (array) config('security-defense.dashboard.opaque_path'));
    }
}