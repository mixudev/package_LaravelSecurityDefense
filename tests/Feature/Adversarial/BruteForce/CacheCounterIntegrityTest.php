<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature\Adversarial\BruteForce;

use PHPUnit\Framework\Attributes\DataProvider;
use Illuminate\Support\Facades\Cache;
use Mixudev\SecurityDefense\DTO\SecurityEvent;
use Mixudev\SecurityDefense\Rules\BruteForceRule;
use Mixudev\SecurityDefense\Tests\TestCase;

final class CacheCounterIntegrityTest extends TestCase
{
    protected function setUp(): void { parent::setUp(); Cache::flush(); config()->set('security-defense.detection.rules.brute_force.threshold', 4); }

    #[DataProvider('poisoningProvider')]
    public function test_counter_seed_cannot_be_poisoned_to_suppress_detection(mixed $seed): void
    {
        $rule = app(BruteForceRule::class);
        for ($i = 0; $i < 3; $i++) $rule->evaluate(new SecurityEvent('198.51.100.44', 'poison@example.test', 'LoginFailed'));
        Cache::put('security_defense:' . 'brute_force:' . md5('poison@example.test') . ':count', $seed, 60);
        $result = $rule->evaluate(new SecurityEvent('198.51.100.44', 'poison@example.test', 'LoginFailed'));
        $this->assertNotNull($result);
    }

    #[DataProvider('targetProvider')]
    public function test_cache_state_isolated_between_targets(string $first, string $second): void
    {
        $rule = app(BruteForceRule::class);
        for ($i = 0; $i < 4; $i++) $rule->evaluate(new SecurityEvent('198.51.100.45', $first, 'LoginFailed'));
        $this->assertNull($rule->evaluate(new SecurityEvent('198.51.100.45', $second, 'LoginFailed')));
    }

    public static function poisoningProvider(): array { return ['zero' => [0], 'negative' => [-99], 'string' => ['0'], 'null' => [null], 'array' => [[]], 'huge' => [PHP_INT_MAX]]; }
    public static function targetProvider(): array { return ['different user' => ['alpha@test', 'beta@test'], 'different ip anonymous' => ['anonymous', 'anonymous-other'], 'case' => ['Alpha@Test', 'alpha@test'], 'long identifier' => [str_repeat('a', 120), str_repeat('b', 120)]]; }
}
