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
        Config::set('security-defense.middleware.user_agent_anomaly.block_headless_clients', false);

        $this->toggle('block_headless_clients', 1)
            ->assertRedirect()
            ->assertSessionHas('status_message', 'Quick-action [block_headless_clients] enabled and saved permanently.');

        $loaded = require $this->tempOverrides;
        $this->assertTrue($loaded['middleware.user_agent_anomaly.block_headless_clients']);
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