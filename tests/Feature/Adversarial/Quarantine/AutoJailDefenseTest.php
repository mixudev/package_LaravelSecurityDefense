<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature\Adversarial\Quarantine;

use PHPUnit\Framework\Attributes\DataProvider;
use Illuminate\Support\Facades\Cache;
use Mixudev\SecurityDefense\DTO\SecurityEvent;
use Mixudev\SecurityDefense\Services\IpQuarantineService;
use Mixudev\SecurityDefense\Tests\TestCase;

final class AutoJailDefenseTest extends TestCase
{
    protected function setUp(): void { parent::setUp(); Cache::flush(); config()->set('security-defense.middleware.quarantine.whitelist', []); }

    #[DataProvider('attackProvider')]
    public function test_critical_attack_ip_remains_quarantined_until_pardoned(string $ip, string $reason): void
    {
        $service = app(IpQuarantineService::class);
        $this->assertTrue($service->jail($ip, 300, $reason));
        $this->assertTrue($service->isQuarantined($ip));
        $service->pardon($ip);
        $this->assertFalse($service->isQuarantined($ip));
    }

    #[DataProvider('eventProvider')]
    public function test_event_shape_preserves_attacker_ip_for_quarantine_boundary(string $ip, string $identifier): void
    {
        $event = new SecurityEvent($ip, $identifier, 'LoginFailed');
        $service = app(IpQuarantineService::class);
        $this->assertTrue($service->jail($event->ip, 60, 'event-driven attack'));
        $this->assertTrue($service->isQuarantined($ip));
    }

    public static function attackProvider(): array { return ['spray' => ['192.0.2.10', 'distributed spray'], 'stuffing' => ['192.0.2.11', 'credential stuffing'], 'brute force' => ['192.0.2.12', 'brute force'], 'flood' => ['192.0.2.13', 'request flood'], 'ipv6' => ['2001:db8::13', 'critical ipv6 attack']]; }
    public static function eventProvider(): array { return ['normal' => ['198.51.100.20', 'user@example.test'], 'rotated' => ['198.51.100.21', 'user@example.test'], 'ipv6' => ['2001:db8::20', 'admin@example.test'], 'anonymous' => ['198.51.100.22', 'anonymous'], 'trimmed' => ['198.51.100.23', ' target ']]; }
}
