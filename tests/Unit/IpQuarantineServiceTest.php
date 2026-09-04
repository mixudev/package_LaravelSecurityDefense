<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Unit;

use Mixudev\SecurityDefense\Services\IpQuarantineService;
use Mixudev\SecurityDefense\Tests\TestCase;

class IpQuarantineServiceTest extends TestCase
{
    public function test_it_jails_and_pardons_an_ip(): void
    {
        $service = app(IpQuarantineService::class);
        $badIp = '203.0.113.88';

        $this->assertFalse($service->isQuarantined($badIp));

        // Jail the IP
        $jailed = $service->jail($badIp, 600, 'SQL injection attempt');
        $this->assertTrue($jailed);
        $this->assertTrue($service->isQuarantined($badIp));

        $details = $service->getDetails($badIp);
        $this->assertNotNull($details);
        $this->assertEquals($badIp, $details['ip']);
        $this->assertEquals('SQL injection attempt', $details['reason']);

        // Pardon the IP
        $service->pardon($badIp);
        $this->assertFalse($service->isQuarantined($badIp));
    }

    public function test_whitelisted_ip_cannot_be_jailed(): void
    {
        config()->set('security-defense.middleware.quarantine.whitelist', ['127.0.0.1', '10.0.0.5']);

        $service = app(IpQuarantineService::class);

        $this->assertFalse($service->jail('127.0.0.1'));
        $this->assertFalse($service->isQuarantined('127.0.0.1'));

        $this->assertFalse($service->jail('10.0.0.5'));
        $this->assertFalse($service->isQuarantined('10.0.0.5'));
    }
}
