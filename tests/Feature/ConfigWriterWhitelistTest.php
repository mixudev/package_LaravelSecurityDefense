<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature;

use Illuminate\Support\Facades\Config;
use Mixudev\SecurityDefense\Services\ConfigWriterService;
use Mixudev\SecurityDefense\Services\IpQuarantineService;
use Mixudev\SecurityDefense\Tests\TestCase;

class ConfigWriterWhitelistTest extends TestCase
{
    protected string $tempOverrides;

    protected function setUp(): void
    {
        parent::setUp();

        // Isolated overrides file path that never touches the real config dir.
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

    private function writer(): ConfigWriterService
    {
        return new ConfigWriterService($this->tempOverrides);
    }

    public function test_config_writer_persists_whitelist_override(): void
    {
        Config::set('security-defense.middleware.quarantine.whitelist', ['127.0.0.1', '::1']);

        $writer = $this->writer();
        $result = $writer->write([
            'middleware.quarantine.whitelist' => ['127.0.0.1', '::1', '203.0.113.50'],
        ]);

        $this->assertTrue($result);

        $contents = file_get_contents($this->tempOverrides);
        $this->assertStringContainsString("'middleware.quarantine.whitelist'", $contents);
        $this->assertStringContainsString("'203.0.113.50'", $contents);

        // Written file must be valid PHP returning the dot-key array.
        $loaded = require $this->tempOverrides;
        $this->assertSame(
            ['127.0.0.1', '::1', '203.0.113.50'],
            $loaded['middleware.quarantine.whitelist']
        );

        // Runtime config must reflect the new value immediately.
        $this->assertSame(['127.0.0.1', '::1', '203.0.113.50'], config('security-defense.middleware.quarantine.whitelist'));
    }

    public function test_config_writer_writes_scalar_override(): void
    {
        Config::set('security-defense.middleware.quarantine.persist_to_database', false);

        $result = $this->writer()->write([
            'middleware.quarantine.persist_to_database' => true,
        ]);

        $this->assertTrue($result);

        $loaded = require $this->tempOverrides;
        $this->assertTrue($loaded['middleware.quarantine.persist_to_database']);
        $this->assertTrue(config('security-defense.middleware.quarantine.persist_to_database'));
    }

    public function test_ip_whitelist_service_updates_override_and_pardons(): void
    {
        Config::set('security-defense.middleware.quarantine.whitelist', ['127.0.0.1', '::1']);

        $service = new IpQuarantineService();
        // Bind the isolated overrides writer into the container.
        $this->app->instance(ConfigWriterService::class, $this->writer());

        // Jail an IP first.
        $service->jail('203.0.113.77', 9999, 'Test attack');

        $this->assertTrue($service->isQuarantined('203.0.113.77'));

        $result = $service->whitelistIp('203.0.113.77');

        $this->assertTrue($result);
        $this->assertTrue($service->isWhitelisted('203.0.113.77'));
        $this->assertFalse($service->isQuarantined('203.0.113.77'));

        // Whitelist persisted to overrides temp file.
        $loaded = require $this->tempOverrides;
        $this->assertContains('203.0.113.77', $loaded['middleware.quarantine.whitelist']);
    }
}