<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature\Adversarial\BruteForce;

use PHPUnit\Framework\Attributes\DataProvider;
use Illuminate\Support\Facades\Cache;
use Mixudev\SecurityDefense\DTO\SecurityEvent;
use Mixudev\SecurityDefense\Rules\BruteForceRule;
use Mixudev\SecurityDefense\Tests\TestCase;

final class BruteForceThresholdTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        Cache::flush();
        config()->set('security-defense.detection.rules.brute_force.threshold', 5);
        config()->set('security-defense.detection.rules.brute_force.window', 60);
    }

    #[DataProvider('thresholdProvider')]
    public function test_lockout_starts_at_threshold(int $attempts, bool $blocked): void
    {
        $rule = app(BruteForceRule::class);
        $result = null;
        for ($i = 0; $i < $attempts; $i++) {
            $result = $rule->evaluate(new SecurityEvent('198.51.100.10', 'victim@example.test', 'LoginFailed'));
        }
        $this->assertSame($blocked, $result !== null, "attempt count {$attempts}");
    }

    #[DataProvider('eventProvider')]
    public function test_only_configured_failure_events_increment(string $event, bool $blocked): void
    {
        $rule = app(BruteForceRule::class);
        for ($i = 0; $i < 5; $i++) {
            $result = $rule->evaluate(new SecurityEvent('198.51.100.11', 'target@example.test', $event));
        }
        $this->assertSame($blocked, isset($result) && $result !== null);
    }

    public static function thresholdProvider(): array
    {
        return ['under one' => [4, false], 'exact threshold' => [5, true], 'over one' => [6, true], 'large burst' => [20, true]];
    }

    public static function eventProvider(): array
    {
        return ['login failed' => ['LoginFailed', true], 'otp failed' => ['OTP_FAILED', true], 'success ignored' => ['LoginSucceeded', false], 'logout ignored' => ['Logout', false], 'generic ignored' => ['GenericSecurityEvent', false], 'case mismatch ignored' => ['loginfailed', false]];
    }
}
