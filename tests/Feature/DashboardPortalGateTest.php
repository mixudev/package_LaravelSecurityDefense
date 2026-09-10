<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature;

use Mixudev\SecurityDefense\Tests\TestCase;

final class DashboardPortalGateTest extends TestCase
{
    private const TOKEN = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);
        $app['config']->set('app.key', 'base64:7VzK9gG2e+x8UfXoN9uC7x/2j6yD8Hw0Z1A2B3C4D5E=');
        $app['env'] = 'local';
        $app['config']->set('security-defense.dashboard.opaque_path.enabled', true);
        putenv('SECURITY_DEFENSE_DASHBOARD_PATH=' . self::TOKEN);
    }

    protected function tearDown(): void
    {
        putenv('SECURITY_DEFENSE_DASHBOARD_PATH');
        parent::tearDown();
    }

    public function test_predictable_entry_is_secure_gate_without_opaque_token_leak(): void
    {
        $response = $this->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
            ->get('/security-defense');

        $response->assertOk();
        $response->assertSee('Secure entry');
        $response->assertSee('Proceed to dashboard');
        $response->assertDontSee(self::TOKEN);
        $response->assertDontSee('/' . self::TOKEN);
        self::assertNull($response->headers->get('Location'));
    }

    public function test_gate_action_redirects_server_side_only_after_local_access_check(): void
    {
        $csrf = 'portal-gate-csrf-token';
        $response = $this->withSession(['_token' => $csrf])
            ->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
            ->post('/security-defense/enter', ['_token' => $csrf]);

        // Relative Location — never an absolute URL derived from Host header.
        self::assertSame('/' . self::TOKEN, $response->headers->get('Location'));
        self::assertSame('', (string) $response->getContent());
    }

    public function test_gate_redirect_ignores_attacker_host_and_user_redirect_inputs(): void
    {
        $csrf = 'portal-gate-csrf-token';
        $response = $this->withSession(['_token' => $csrf])
            ->withServerVariables(['REMOTE_ADDR' => '127.0.0.1', 'HTTP_HOST' => 'attacker.test'])
            ->post('/security-defense/enter?next=https://attacker.test/leak', [
                '_token' => $csrf,
                'redirect' => 'https://attacker.test/leak',
            ]);

        self::assertSame('/' . self::TOKEN, $response->headers->get('Location'));
        self::assertStringNotContainsString('attacker.test', (string) $response->headers->get('Location'));
    }

    public function test_gate_action_denies_same_as_dashboard_when_access_check_fails(): void
    {
        $csrf = 'portal-gate-csrf-token';
        $response = $this->withSession(['_token' => $csrf])
            ->withServerVariables(['REMOTE_ADDR' => '203.0.113.10'])
            ->post('/security-defense/enter', ['_token' => $csrf]);

        $response->assertForbidden();
        $response->assertDontSee(self::TOKEN);
    }

    public function test_gate_enter_is_post_only_and_get_cannot_verify(): void
    {
        $this->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
            ->get('/security-defense/enter')
            ->assertMethodNotAllowed();
    }

    public function test_opaque_mode_switch_is_explicitly_configured(): void
    {
        self::assertTrue(config('security-defense.dashboard.opaque_path.enabled'));
        self::assertSame('security-defense', config('security-defense.dashboard.path'));
    }
}
