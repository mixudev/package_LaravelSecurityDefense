<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature;

use Mixudev\SecurityDefense\Services\IpQuarantineService;
use Mixudev\SecurityDefense\Tests\TestCase;

class QuarantineTtlRegressionTest extends TestCase
{
    private const IP = '203.0.113.77';

    public function test_a_shorter_rejail_cannot_shorten_an_existing_jail(): void
    {
        $service = app(IpQuarantineService::class);

        $this->assertTrue($service->jail(self::IP, 3600, 'severe flood'));
        $longExpiry = $service->getDetails(self::IP)['expires_at'];

        $this->assertTrue($service->jail(self::IP, 60, 're-trigger'));
        $shortExpiry = $service->getDetails(self::IP)['expires_at'];

        $this->assertGreaterThanOrEqual($longExpiry, $shortExpiry);
    }
}
