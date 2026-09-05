<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature;

use Illuminate\Support\Facades\Config;
use Mixudev\SecurityDefense\Services\ConfigWriterService;
use Mixudev\SecurityDefense\Services\IpQuarantineService;
use Mixudev\SecurityDefense\Tests\TestCase;

class ConfigWriterWhitelistTest extends TestCase
{
    protected string $tempConfig;

    protected function setUp(): void
    {
        parent::setUp();

        // Create a temp published-style config file mirroring the quarantine block.
        $this->tempConfig = tempnam(sys_get_temp_dir(), 'seccfg') . '.php';
        file_put_contents($this->tempConfig, <<<'PHP'
<?php

return [

    'middleware' => [
        'quarantine' => [
            'enabled' => true,
            'duration' => 900,
            'persist_to_database' => false,
            'whitelist' => [
                '127.0.0.1',
                '::1',
            ],
        ],
    ],

];
PHP);
    }

    protected function tearDown(): void
    {
        if (file_exists($this->tempConfig)) {
            @unlink($this->tempConfig);
        }
        parent::tearDown();
    }

    public function test_config_writer_persists_whitelist_to_file(): void
    {
        Config::set('security-defense.middleware.quarantine.whitelist', ['127.0.0.1', '::1']);

        $writer = new ConfigWriterService($this->tempConfig);
        $result = $writer->write([
            'middleware.quarantine.whitelist' => ['127.0.0.1', '::1', '203.0.113.50'],
        ]);

        $this->assertTrue($result);

        $contents = file_get_contents($this->tempConfig);
        $this->assertStringContainsString("'203.0.113.50'", $contents);

        // The written file must remain valid PHP.
        $loaded = require $this->tempConfig;
        $this->assertSame(
            ['127.0.0.1', '::1', '203.0.113.50'],
            $loaded['middleware']['quarantine']['whitelist']
        );
    }

    public function test_config_writer_writes_scalar_value(): void
    {
        Config::set('security-defense.middleware.quarantine.persist_to_database', false);

        $writer = new ConfigWriterService($this->tempConfig);
        $result = $writer->write([
            'middleware.quarantine.persist_to_database' => true,
        ]);

        $this->assertTrue($result);

        $loaded = require $this->tempConfig;
        $this->assertTrue($loaded['middleware']['quarantine']['persist_to_database']);
    }

    public function test_ip_whitelist_service_updates_config_and_pardons(): void
    {
        Config::set('security-defense.middleware.quarantine.whitelist', ['127.0.0.1', '::1']);

        $service = new IpQuarantineService();
        // Bind the temp config path into the container so whitelistIp writes there.
        $this->app->instance(ConfigWriterService::class, new ConfigWriterService($this->tempConfig));

        // Jail an IP first.
        $service->jail('203.0.113.77', 9999, 'Test attack');

        $this->assertTrue($service->isQuarantined('203.0.113.77'));

        $result = $service->whitelistIp('203.0.113.77');

        $this->assertTrue($result);
        $this->assertTrue($service->isWhitelisted('203.0.113.77'));
        $this->assertFalse($service->isQuarantined('203.0.113.77'));

        // Whitelist persisted to the temp file.
        $loaded = require $this->tempConfig;
        $this->assertContains('203.0.113.77', $loaded['middleware']['quarantine']['whitelist']);
    }
}