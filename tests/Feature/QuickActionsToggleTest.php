<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature;

use Illuminate\Support\Facades\Config;
use Illuminate\Support\Str;
use Mixudev\SecurityDefense\Services\ConfigWriterService;
use Mixudev\SecurityDefense\Tests\TestCase;

class QuickActionsToggleTest extends TestCase
{
    protected string $tempOverrides;

    protected function setUp(): void
    {
        parent::setUp();

        $this->tempOverrides = tempnam(sys_get_temp_dir(), 'secover') . '.php';
        if (file_exists($this->tempOverrides)) {
            @unlink($this->tempOverrides);
        }

        $this->app->instance(ConfigWriterService::class, new ConfigWriterService($this->tempOverrides));
    }

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app['config']->set('app.key', 'base64:7VzK9gG2e+x8UfXoN9uC7x/2j6yD8Hw0Z1A2B3C4D5E=');
        $app['config']->set('security-defense.dashboard.enabled', true);
        $app['config']->set('security-defense.dashboard.local_only', true);
        $app['config']->set('security-defense.dashboard.allowed_ips', ['127.0.0.1', '::1']);
        $app['config']->set('security-defense.enabled', true);
        $app['config']->set('security-defense.detection.enabled', true);
        $app['config']->set('security-defense.detection.rules.user_agent_anomaly.enabled', true);
        $app['config']->set('security-defense.middleware.user_agent_anomaly.enabled', true);
    }

    protected function tearDown(): void
    {
        if (file_exists($this->tempOverrides)) {
            @unlink($this->tempOverrides);
        }
        parent::tearDown();
    }

    private function toggle(string $key, int $value): \Illuminate\Testing\TestResponse
    {
        $token = Str::random(40);
        $this->app['env'] = 'local';

        return $this->withSession(['_token' => $token])
            ->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
            ->post(route('security-defense.toggle-setting'), [
                '_token' => $token,
                'key' => $key,
                'value' => $value,
            ]);
    }

    public function test_toggle_blocks_headless_clients_persists(): void
    {
        Config::set('security-defense.detection.rules.user_agent_anomaly.block_headless_clients', false);

        $this->toggle('block_headless_clients', 1)
            ->assertRedirect()
            ->assertSessionHas('status_message', 'Quick-action [block_headless_clients] enabled and saved permanently.');

        $loaded = require $this->tempOverrides;
        $this->assertTrue($loaded['detection.rules.user_agent_anomaly.block_headless_clients']);
    }

    public function test_toggle_key_matches_rule_read_key(): void
    {
        // Regression: the dashboard wrote to middleware.user_agent_anomaly.block_headless_clients
        // while UserAgentAnomalyRule read detection.rules.user_agent_anomaly.block_headless_clients.
        // This test asserts the written override key exactly matches what the rule inspects.
        $this->toggle('block_headless_clients', 1)->assertRedirect();

        $loaded = require $this->tempOverrides;

        // 1. The persisted key must be the detection.rules one:
        $this->assertArrayHasKey(
            'detection.rules.user_agent_anomaly.block_headless_clients',
            $loaded,
            'The written key must match what UserAgentAnomalyRule actually reads.'
        );

        // 2. Feed the written override into the rule's config and verify the rule respects it.
        config()->set('security-defense.detection.rules.user_agent_anomaly.block_headless_clients', $loaded['detection.rules.user_agent_anomaly.block_headless_clients']);
        config()->set('security-defense.detection.rules.user_agent_anomaly.enabled', true);

        $rule = app(\Mixudev\SecurityDefense\Rules\UserAgentAnomalyRule::class);
        $event = new \Mixudev\SecurityDefense\DTO\SecurityEvent(
            ip: '198.51.107.1',
            identifier: 'probe',
            eventType: 'http_request',
            userAgent: 'python-requests/2.31.0',
        );

        $threat = $rule->evaluate($event);
        $this->assertNotNull($threat, 'Headless client must be detected as a threat when the toggle is on.');
        $this->assertSame('user_agent_anomaly', $threat->threatType);
        $this->assertSame('python_requests', $threat->metadata['detected_tool']);
    }

    public function test_toggle_csp_armor_persists(): void
    {
        $this->toggle('csp_armor', 0)
            ->assertRedirect();

        $loaded = require $this->tempOverrides;
        $this->assertFalse($loaded['csp_armor.enabled']);
        $this->assertFalse(config('security-defense.csp_armor.enabled'));
    }

    public function test_toggle_async_queue_persists(): void
    {
        $this->toggle('async_queue', 1)
            ->assertRedirect();

        $loaded = require $this->tempOverrides;
        $this->assertTrue($loaded['data_audit.queue.enabled']);
        $this->assertTrue(config('security-defense.data_audit.queue.enabled'));
    }

    public function test_toggle_rejects_unknown_key(): void
    {
        $this->toggle('database.password', 1)
            ->assertRedirect()
            ->assertSessionHas('error_message');
    }
}