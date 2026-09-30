<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature;

use Mixudev\SecurityDefense\Models\SecurityAlert;
use Mixudev\SecurityDefense\Support\DashboardCapability;
use Mixudev\SecurityDefense\Support\OpaqueRouteAliases;
use Mixudev\SecurityDefense\Tests\TestCase;

/**
 * Regression: with `dashboard.opaque_path.enabled = true` the dashboard routes
 * live under an extra `{opaque}` prefix segment, so Laravel handed that STRING to
 * the controller's first positional parameter.
 *
 * `DashboardController::acknowledge(SecurityAlert $alert)` therefore always threw
 *
 *   TypeError: acknowledge(): Argument #1 ($alert) must be of type
 *   Mixudev\SecurityDefense\Models\SecurityAlert, string given
 *
 * and every acknowledge/resolve POST returned HTTP 500. The operator could not
 * triage an alert at all while opaque mode was on.
 *
 * Both actions now resolve the alert from the named `{alert}` route parameter.
 */
final class OpaqueModeAlertActionDispatchTest extends TestCase
{
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);
        $app['config']->set('app.key', 'base64:7VzK9gG2e+x8UfXoN9uC7x/2j6yD8Hw0Z1A2B3C4D5E=');
        $app['env'] = 'local';
        $app['config']->set('security-defense.dashboard.opaque_path.enabled', true);
    }

    private function makeAlert(): SecurityAlert
    {
        return SecurityAlert::query()->create([
            'severity'        => 'high',
            'threat_type'     => 'test_threat',
            'fingerprint'     => 'fp-opaque-action',
            'rule_identifier' => 'test_rule',
        ]);
    }

    private function authorizedSession(): string
    {
        $this->app['session']->setId('opaque-action-session');
        $path = app(DashboardCapability::class)->sessionPath('opaque-action-session');

        $this->withSession([
            'security-defense.dashboard-authorized'   => true,
            'security-defense.dashboard-session-path' => $path,
            '_token'                                  => 'opaque-action-token',
        ]);

        return $path;
    }

    public function test_acknowledge_succeeds_under_opaque_mode(): void
    {
        $alert = $this->makeAlert();
        $path = $this->authorizedSession();

        $this->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
            ->post(
                '/' . $path . '/' . OpaqueRouteAliases::path('security-defense.alerts.acknowledge') . '/' . $alert->id,
                ['_token' => 'opaque-action-token']
            )
            ->assertRedirect();

        self::assertSame(
            SecurityAlert::STATUS_ACKNOWLEDGED,
            $alert->fresh()?->status,
            'acknowledge() did not mutate the alert under opaque mode'
        );
    }

    public function test_resolve_succeeds_under_opaque_mode(): void
    {
        $alert = $this->makeAlert();
        $path = $this->authorizedSession();

        $this->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
            ->post(
                '/' . $path . '/' . OpaqueRouteAliases::path('security-defense.alerts.resolve') . '/' . $alert->id,
                ['_token' => 'opaque-action-token']
            )
            ->assertRedirect();

        self::assertSame(
            SecurityAlert::STATUS_RESOLVED,
            $alert->fresh()?->status,
            'resolve() did not mutate the alert under opaque mode'
        );
    }

    public function test_missing_alert_still_returns_not_found_instead_of_500(): void
    {
        $path = $this->authorizedSession();

        $this->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
            ->post(
                '/' . $path . '/' . OpaqueRouteAliases::path('security-defense.alerts.acknowledge') . '/999999',
                ['_token' => 'opaque-action-token']
            )
            ->assertNotFound();
    }
}
