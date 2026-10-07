<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature\Adversarial\BruteForce;

use PHPUnit\Framework\Attributes\DataProvider;
use Illuminate\Support\Facades\Cache;
use Mixudev\SecurityDefense\DTO\SecurityEvent;
use Mixudev\SecurityDefense\Rules\RateLimitBypassRule;
use Mixudev\SecurityDefense\Tests\TestCase;

final class RateLimitBypassAdversarialTest extends TestCase
{
    protected function setUp(): void { parent::setUp(); Cache::flush(); config()->set('security-defense.detection.rules.rate_limit_bypass.threshold', 5); }

    #[DataProvider('chainProvider')]
    public function test_long_forwarded_chains_are_rejected(string $chain, bool $blocked): void
    {
        $rule = app(RateLimitBypassRule::class);
        $result = $rule->evaluate(new SecurityEvent('198.51.100.30', 'anonymous', 'GenericSecurityEvent', null, 'attacker', ['headers' => ['x-forwarded-for' => $chain]]));
        $this->assertSame($blocked, $result !== null);
    }

    #[DataProvider('burstProvider')]
    public function test_rotating_ip_burst_hits_rate_limit_counter(array $ips, bool $blocked): void
    {
        $rule = app(RateLimitBypassRule::class); $result = null;
        foreach ($ips as $ip) $result = $rule->evaluate(new SecurityEvent($ip, 'anonymous', 'GenericSecurityEvent', null, 'same-agent'));
        $this->assertSame($blocked, $result !== null);
    }

    public static function chainProvider(): array
    {
        $cases = ['empty' => ['', false], 'one' => ['198.51.100.1', false], 'five' => [implode(',', array_map(fn($n) => "198.51.100.{$n}", range(1,5))), false], 'six' => [implode(',', array_map(fn($n) => "198.51.100.{$n}", range(1,6))), true]];
        for ($n = 7; $n <= 35; $n++) $cases["chain {$n}"] = [implode(',', array_map(fn($i) => "192.0.2.{$i}", range(1,$n))), true];
        return $cases;
    }
    public static function burstProvider(): array
    {
        $cases = ['under' => [array_map(fn($n) => "203.0.113.{$n}", range(1,4)), false], 'exact' => [array_map(fn($n) => "203.0.113.{$n}", range(1,5)), true], 'over' => [array_map(fn($n) => "203.0.113.{$n}", range(1,8)), true]];
        for ($n = 1; $n <= 20; $n++) $cases["rotating burst {$n}"] = [array_map(fn($i) => "198.18.{$n}.{$i}", range(1, 5)), true];
        return $cases;
    }
}
