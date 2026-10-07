<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature\Adversarial\BruteForce;

use PHPUnit\Framework\Attributes\DataProvider;
use Illuminate\Support\Facades\Cache;
use Mixudev\SecurityDefense\DTO\SecurityEvent;
use Mixudev\SecurityDefense\Rules\BruteForceRule;
use Mixudev\SecurityDefense\Tests\TestCase;

final class BruteForceWindowEdgeTest extends TestCase
{
    protected function setUp(): void { parent::setUp(); Cache::flush(); config()->set('security-defense.detection.rules.brute_force.threshold', 3); config()->set('security-defense.detection.rules.brute_force.window', 60); }

    #[DataProvider('boundaryProvider')]
    public function test_lockout_boundary_is_exact(int $attempts, bool $blocked): void
    {
        $rule = app(BruteForceRule::class);
        $result = null;
        for ($i = 0; $i < $attempts; $i++) {
            $result = $rule->evaluate(new SecurityEvent('198.51.100.70', 'edge@test', 'LoginFailed'));
        }
        $this->assertSame($blocked, $result !== null);
    }

    #[DataProvider('targetProvider')]
    public function test_window_counters_are_isolated_by_target(string $first, string $second): void
    {
        $rule = app(BruteForceRule::class);
        for ($i = 0; $i < 3; $i++) {
            $firstResult = $rule->evaluate(new SecurityEvent('198.51.100.71', $first, 'LoginFailed'));
        }
        $secondResult = $rule->evaluate(new SecurityEvent('198.51.100.71', $second, 'LoginFailed'));
        $this->assertNotNull($firstResult);
        $this->assertNull($secondResult);
    }

    public static function boundaryProvider(): array { return ['two under' => [2, false], 'exact third' => [3, true], 'four over' => [4, true], 'large burst' => [20, true]]; }
    public static function targetProvider(): array { return ['different accounts' => ['first@test', 'second@test'], 'different case' => ['First@Test', 'first@test'], 'long identifiers' => [str_repeat('a', 100), str_repeat('b', 100)], 'different users' => ['admin@test', 'guest@test']]; }
}
