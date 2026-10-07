<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature;

use Illuminate\Auth\GenericUser;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Gate;
use Mixudev\SecurityDefense\Tests\TestCase;

class DashboardAuthorizationRoleTest extends TestCase
{
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app['config']->set('app.key', 'base64:7VzK9gG2e+x8UfXoN9uC7x/2j6yD8Hw0Z1A2B3C4D5E=');
        $app['config']->set('security-defense.dashboard.enabled', true);
        $app['config']->set('security-defense.dashboard.local_only', true);
        $app['config']->set('security-defense.dashboard.allowed_ips', ['127.0.0.1', '::1']);
    }

    public function test_role_mode_never_accepts_request_role_field(): void
    {
        $this->app['env'] = 'local';
        config()->set('security-defense.dashboard.authorization', [
            'enabled' => true,
            'mode' => 'role',
            'roles' => ['security-admin'],
            'role_attribute' => 'roles',
        ]);

        Auth::setUser(new GenericUser(['id' => 99, 'roles' => ['user']]));

        $response = $this->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
            ->withHeaders(['Accept' => 'application/json'])
            ->get('/security-defense?role=security-admin&roles[]=security-admin');
        $response->assertForbidden();
    }

    public function test_gate_mode_ignores_request_gate_fields(): void
    {
        $this->app['env'] = 'local';
        config()->set('security-defense.dashboard.authorization', [
            'enabled' => true,
            'mode' => 'gate',
            'name' => 'viewSecurityDefenseDashboard',
        ]);
        Gate::define('viewSecurityDefenseDashboard', fn ($user) => $user !== null && $user->getAuthIdentifier() == 1);

        Auth::setUser(new GenericUser(['id' => 2]));
        $response = $this->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
            ->get('/security-defense?viewSecurityDefenseDashboard=true');
        $response->assertForbidden();
    }

    public function test_custom_resolver_must_be_callable(): void
    {
        $this->app['env'] = 'local';
        config()->set('security-defense.dashboard.authorization', [
            'enabled' => true,
            'mode' => 'custom',
            'resolver' => NonCallableClass::class,
        ]);
        Auth::setUser(new GenericUser(['id' => 5]));
        $response = $this->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
            ->get('/security-defense');
        $response->assertForbidden();
    }

    public function test_custom_resolver_called_with_user_and_request(): void
    {
        $this->app->singleton(CustomAuthResolver::class, fn () => new CustomAuthResolver());
        $this->app['env'] = 'local';
        config()->set('security-defense.dashboard.authorization', [
            'enabled' => true,
            'mode' => 'custom',
            'resolver' => CustomAuthResolver::class,
        ]);
        Auth::setUser(new GenericUser(['id' => 10]));
        $response = $this->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
            ->get('/security-defense');
        $response->assertOk();
    }
}

final class NonCallableClass
{
}

final class CustomAuthResolver
{
    public function __invoke($user, $request, array $config): bool
    {
        return $user->getAuthIdentifier() === 10;
    }
}
