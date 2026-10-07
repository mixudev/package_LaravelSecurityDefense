<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature\Adversarial\BruteForce;

use PHPUnit\Framework\Attributes\DataProvider;
use Illuminate\Support\Facades\Cache;
use Mixudev\SecurityDefense\DTO\SecurityEvent;
use Mixudev\SecurityDefense\Rules\BruteForceRule;
use Mixudev\SecurityDefense\Tests\TestCase;

final class BruteForceIdentityTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp(); Cache::flush();
        config()->set('security-defense.detection.rules.brute_force.threshold', 3);
    }

    #[DataProvider('identifiers')]
    public function test_counter_is_keyed_by_account_identifier(string $first, string $second, bool $same): void
    {
        $rule = app(BruteForceRule::class);
        for ($i = 0; $i < 2; $i++) $rule->evaluate(new SecurityEvent('203.0.113.5', $first, 'LoginFailed'));
        $result = $rule->evaluate(new SecurityEvent('203.0.113.5', $second, 'LoginFailed'));
        $this->assertSame($same, $result !== null);
    }

    #[DataProvider('ips')]
    public function test_rotating_source_ips_cannot_reset_account_counter(string ...$ips): void
    {
        $rule = app(BruteForceRule::class); $result = null;
        foreach ($ips as $ip) $result = $rule->evaluate(new SecurityEvent($ip, 'shared-target@example.test', 'LoginFailed'));
        $this->assertNotNull($result);
    }

    public static function identifiers(): array
    {
        return ['same' => ['User@Example.Test', 'User@Example.Test', true], 'different' => ['one@example.test', 'two@example.test', false], 'case variant is separate key' => ['Case@Test', 'case@test', false], 'empty normalized anonymous' => ['', 'anonymous', true]];
    }

    public static function ips(): array
    {
        return [
            'rotating 1' => ['198.18.1.1', '198.18.1.2', '198.18.1.3'],
            'rotating 2' => ['198.18.2.1', '198.18.2.2', '198.18.2.3'],
            'rotating 3' => ['198.18.3.1', '198.18.3.2', '198.18.3.3'],
            'rotating 4' => ['198.18.4.1', '198.18.4.2', '198.18.4.3'],
            'rotating 5' => ['198.18.5.1', '198.18.5.2', '198.18.5.3'],
            'rotating 6' => ['198.18.6.1', '198.18.6.2', '198.18.6.3'],
            'rotating 7' => ['198.18.7.1', '198.18.7.2', '198.18.7.3'],
            'rotating 8' => ['198.18.8.1', '198.18.8.2', '198.18.8.3'],
            'rotating 9' => ['198.18.9.1', '198.18.9.2', '198.18.9.3'],
            'rotating 10' => ['198.18.10.1', '198.18.10.2', '198.18.10.3'],
            'rotating 11' => ['198.18.11.1', '198.18.11.2', '198.18.11.3'],
            'rotating 12' => ['198.18.12.1', '198.18.12.2', '198.18.12.3'],
        ];
    }
}
