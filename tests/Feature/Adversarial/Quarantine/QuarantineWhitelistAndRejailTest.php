<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature\Adversarial\Quarantine;

use PHPUnit\Framework\Attributes\DataProvider;
use Illuminate\Support\Facades\Cache;
use Mixudev\SecurityDefense\Services\IpQuarantineService;
use Mixudev\SecurityDefense\Tests\TestCase;

final class QuarantineWhitelistAndRejailTest extends TestCase
{
    protected function setUp(): void { parent::setUp(); Cache::flush(); }

    #[DataProvider('whitelistProvider')]
    public function test_whitelisted_addresses_bypass_jail_only_when_exactly_configured(string $ip, array $whitelist, bool $jailed): void
    {
        config()->set('security-defense.middleware.quarantine.whitelist', $whitelist);
        $service = app(IpQuarantineService::class);
        $this->assertSame($jailed, $service->jail($ip, 120));
        $this->assertSame($jailed, $service->isQuarantined($ip));
    }

    #[DataProvider('durationPairProvider')]
    public function test_rejail_never_shortens_active_quarantine(int $first, int $second): void
    {
        $service = app(IpQuarantineService::class); $ip = '203.0.113.88';
        $this->assertTrue($service->jail($ip, $first)); $long = $service->getDetails($ip)['expires_at'];
        $this->assertTrue($service->jail($ip, $second)); $short = $service->getDetails($ip)['expires_at'];
        $this->assertGreaterThanOrEqual($long, $short);
    }

    public static function whitelistProvider(): array { return ['loopback default' => ['127.0.0.1', ['127.0.0.1'], false], 'ipv6 loopback' => ['::1', ['::1'], false], 'near miss' => ['127.0.0.2', ['127.0.0.1'], true], 'unlisted' => ['198.51.100.9', [], true], 'exact ipv6' => ['2001:db8::9', ['2001:db8::9'], false], 'spoofed prefix' => ['127.0.0.1.evil', ['127.0.0.1'], false]]; }
    public static function durationPairProvider(): array { return ['short retry' => [3600, 1], 'equal' => [60, 60], 'long retry' => [1, 3600], 'default-like' => [900, 30], 'maximum-like' => [86400, 2]]; }
}
