<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature;

use Illuminate\Support\Facades\Config;
use Mixudev\SecurityDefense\Services\ConfigWriterService;
use Mixudev\SecurityDefense\Tests\TestCase;

class OverridesProviderMergeTest extends TestCase
{
    protected string $tempOverrides;

    protected function setUp(): void
    {
        parent::setUp();

        $this->tempOverrides = tempnam(sys_get_temp_dir(), 'secover') . '.php';
        if (file_exists($this->tempOverrides)) {
            @unlink($this->tempOverrides);
        }
    }

    protected function tearDown(): void
    {
        if (file_exists($this->tempOverrides)) {
            @unlink($this->tempOverrides);
        }
        parent::tearDown();
    }

    public function test_dot_key_override_is_written_correctly(): void
    {
        (new ConfigWriterService($this->tempOverrides))->write([
            'csp_armor.enabled' => false,
            'data_audit.queue.enabled' => true,
            'middleware.user_agent_anomaly.block_headless_clients' => true,
        ]);

        $loaded = require $this->tempOverrides;
        $this->assertSame(false, $loaded['csp_armor.enabled']);
        $this->assertSame(true, $loaded['data_audit.queue.enabled']);
        $this->assertSame(true, $loaded['middleware.user_agent_anomaly.block_headless_clients']);
    }

    public function test_overrides_file_format_is_valid_php(): void
    {
        (new ConfigWriterService($this->tempOverrides))->write([
            'csp_armor.enabled' => false,
        ]);

        $this->assertIsArray(require $this->tempOverrides);
    }

    public function test_data_set_expands_dot_keys_into_nested_config(): void
    {
        Config::set('security-defense.csp_armor.enabled', true);

        // Simulate provider boot expanding overrides.
        $overrides = [
            'csp_armor.enabled' => false,
        ];
        $config = Config::get('security-defense');
        foreach ($overrides as $key => $value) {
            data_set($config, $key, $value);
        }
        Config::set('security-defense', $config);

        $this->assertFalse(config('security-defense.csp_armor.enabled'));
    }
}