<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature\Adversarial\Quarantine;

use PHPUnit\Framework\Attributes\DataProvider;
use Illuminate\Support\Facades\Cache;
use Mixudev\SecurityDefense\Services\IpQuarantineService;
use Mixudev\SecurityDefense\Tests\TestCase;

final class QuarantineBoundaryTest extends TestCase
{
    protected function setUp(): void { parent::setUp(); Cache::flush(); config()->set('security-defense.middleware.quarantine.whitelist', []); }

    #[DataProvider('ipProvider')]
    public function test_only_valid_ip_addresses_can_be_jailed(string $ip, bool $jailed): void
    {
        $service = app(IpQuarantineService::class);
        $this->assertSame($jailed, $service->jail($ip, 60, 'adversarial test'));
        $this->assertSame($jailed, $service->isQuarantined($ip));
    }

    #[DataProvider('durationProvider')]
    public function test_duration_is_clamped_without_disabling_the_jail(?int $duration): void
    {
        $service = app(IpQuarantineService::class);
        $this->assertTrue($service->jail('198.51.100.77', $duration));
        $details = $service->getDetails('198.51.100.77');
        $this->assertNotNull($details);
        $this->assertGreaterThan(time(), $details['expires_at']);
    }

    public static function ipProvider(): array { return ['ipv4' => ['198.51.100.1', true], 'ipv6' => ['2001:db8::1', true], 'bad text' => ['not-an-ip', false], 'empty' => ['', false], 'cidr is not host' => ['198.51.100.0/24', false], 'spoofed header text' => ['X-Forwarded-For: 198.51.100.2', false]]; }
    public static function durationProvider(): array { return ['null' => [null], 'zero' => [0], 'negative' => [-5], 'short' => [1], 'normal' => [300], 'huge' => [PHP_INT_MAX]]; }
}
