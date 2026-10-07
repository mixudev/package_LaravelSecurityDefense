<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature\Adversarial\BruteForce;

use PHPUnit\Framework\Attributes\DataProvider;
use Illuminate\Support\Facades\Cache;
use Mixudev\SecurityDefense\DTO\SecurityEvent;
use Mixudev\SecurityDefense\Rules\DistributedSprayRule;
use Mixudev\SecurityDefense\Tests\TestCase;

final class DistributedSprayTest extends TestCase
{
    protected function setUp(): void { parent::setUp(); Cache::flush(); config()->set('security-defense.detection.rules.distributed_spray.threshold', 5); }

    #[DataProvider('sprayProvider')]
    public function test_many_ips_targeting_one_account_are_detected(array $ips, bool $blocked): void
    {
        $rule = app(DistributedSprayRule::class); $result = null;
        foreach ($ips as $ip) $result = $rule->evaluate(new SecurityEvent($ip, 'spray-target@example.test', 'LoginFailed'));
        $this->assertSame($blocked, $result !== null);
    }

    #[DataProvider('duplicateProvider')]
    public function test_repeated_ip_does_not_fake_distinct_attacker_count(array $ips, int $expected): void
    {
        $rule = app(DistributedSprayRule::class); $result = null;
        foreach ($ips as $ip) $result = $rule->evaluate(new SecurityEvent($ip, 'one-target@example.test', 'LoginFailed'));
        $this->assertSame($expected >= 5, $result !== null);
        if ($result) $this->assertSame($expected, $result->metadata['distinct_ips_count']);
    }

    public static function sprayProvider(): array
    {
        return ['four ips' => [array_map(fn($n) => "192.0.2.{$n}", range(1,4)), false], 'five ips' => [array_map(fn($n) => "192.0.2.{$n}", range(1,5)), true], 'six ips' => [array_map(fn($n) => "192.0.2.{$n}", range(1,6)), true], 'ten ips' => [array_map(fn($n) => "192.0.2.{$n}", range(1,10)), true], 'slow distributed set' => [array_map(fn($n) => "198.51.100.{$n}", range(1,7)), true]];
    }
    public static function duplicateProvider(): array
    {
        return ['all same' => [['192.0.2.1','192.0.2.1','192.0.2.1','192.0.2.1','192.0.2.1'], 1], 'four unique plus repeat' => [['192.0.2.1','192.0.2.2','192.0.2.3','192.0.2.4','192.0.2.4'], 4], 'five unique' => [array_map(fn($n) => "203.0.113.{$n}", range(1,5)), 5]];
    }
}
