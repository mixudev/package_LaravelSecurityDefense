<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature;

use Mixudev\SecurityDefense\Tests\TestCase;

final class OpaquePathRotationTest extends TestCase
{
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);
        $app['config']->set('app.key', 'base64:7VzK9gG2e+x8UfXoN9uC7x/2j6yD8Hw0Z1A2B3C4D5E=');
        $app['env'] = 'local';
        $app['config']->set('security-defense.dashboard.opaque_path.enabled', true);
        $app['config']->set('security-defense.dashboard.opaque_path.ttl_seconds', 60);
    }

    public function test_gate_issues_opaque_capability_without_readable_route_name(): void
    {
        $csrf = 'portal-csrf';
        $response = $this->withSession(['_token' => $csrf])
            ->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
            ->post('/security-defense/enter', ['_token' => $csrf]);

        $response->assertRedirect();
        $location = (string) $response->headers->get('Location');
        self::assertMatchesRegularExpression('#^/[A-Za-z0-9_-]{64,2048}$#', $location);
        self::assertStringNotContainsString('security-defense', $location);
        self::assertStringNotContainsString('dashboard', $location);
    }

    public function test_capability_route_cannot_be_used_without_valid_signature(): void
    {
        $this->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
            ->get('/' . str_repeat('A', 882))
            ->assertNotFound();
    }
}
