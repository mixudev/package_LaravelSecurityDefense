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

    public function test_db_backed_quarantine_survives_cache_clear(): void
    {
        config()->set('security-defense.middleware.quarantine.persist_to_database', true);
        config()->set('security-defense.middleware.quarantine.whitelist', []);

        $service = app(IpQuarantineService::class);
        $ip = '203.0.113.200';

        $service->jail($ip, 600, 'Persistent test');

        // Flush cache to simulate cache clear / multi-server environment
        cache()->flush();

        // Durable DB record must still quarantine the IP
        $this->assertTrue($service->isQuarantined($ip));

        // Pardon clears both cache and DB
        $service->pardon($ip);
        $this->assertFalse($service->isQuarantined($ip));
    }

    public function test_db_exception_after_cache_miss_does_not_block_clean_traffic_by_default(): void
    {
        config()->set('security-defense.middleware.quarantine.persist_to_database', true);
        config()->set('security-defense.middleware.quarantine.db_fail_closed', false);
        config()->set('security-defense.middleware.quarantine.table', 'missing_quarantine_table');
        config()->set('security-defense.middleware.quarantine.whitelist', []);

        $this->assertFalse(app(IpQuarantineService::class)->isQuarantined('203.0.113.201'));
    }

    public function test_db_exception_after_cache_miss_can_fail_closed_for_active_threat_indicators(): void
    {
        config()->set('security-defense.middleware.quarantine.persist_to_database', true);
        config()->set('security-defense.middleware.quarantine.db_fail_closed', true);
        config()->set('security-defense.middleware.quarantine.table', 'missing_quarantine_table');
        config()->set('security-defense.middleware.quarantine.whitelist', []);

        $this->assertTrue(app(IpQuarantineService::class)->isQuarantined('203.0.113.202'));
    }

    public function test_cache_hit_stays_enforced_when_database_is_unavailable(): void
    {
        config()->set('security-defense.middleware.quarantine.persist_to_database', true);
        config()->set('security-defense.middleware.quarantine.table', 'missing_quarantine_table');
        config()->set('security-defense.middleware.quarantine.whitelist', []);

        $service = app(IpQuarantineService::class);
        $service->jail('203.0.113.203', 600);

        $this->assertTrue($service->isQuarantined('203.0.113.203'));
    }

    public function test_invalid_ip_cannot_be_quarantined_or_queried(): void
    {
        $service = app(IpQuarantineService::class);

        $this->assertFalse($service->jail('not-an-ip'));
        $this->assertFalse($service->isQuarantined('not-an-ip'));
        $this->assertNull($service->getDetails('not-an-ip'));
    }

    public function test_duration_is_clamped_and_reason_is_bounded(): void
    {
        $service = app(IpQuarantineService::class);
        $ip = '203.0.113.204';
        $reason = str_repeat('x', 500);

        $this->assertTrue($service->jail($ip, -100, $reason));
        $details = $service->getDetails($ip);
        $this->assertNotNull($details);
        $this->assertSame(255, strlen($details['reason']));
        $this->assertLessThanOrEqual(time() + 2, $details['expires_at']);

        $service->pardon($ip);
        $this->assertTrue($service->jail($ip, PHP_INT_MAX));
        $details = $service->getDetails($ip);
        $this->assertNotNull($details);
        $this->assertLessThanOrEqual(time() + 86401, $details['expires_at']);
    }

    public function test_zero_duration_is_clamped_to_one_second(): void
    {
        $service = app(IpQuarantineService::class);
        $ip = '203.0.113.205';

        $this->assertTrue($service->jail($ip, 0));
        $details = $service->getDetails($ip);
        $this->assertNotNull($details);
        $this->assertGreaterThanOrEqual(time(), $details['expires_at']);
    }
}
