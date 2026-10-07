<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature\Adversarial\BruteForce;

use PHPUnit\Framework\Attributes\DataProvider;
use Illuminate\Support\Facades\Cache;
use Mixudev\SecurityDefense\DTO\SecurityEvent;
use Mixudev\SecurityDefense\Rules\CredentialStuffingRule;
use Mixudev\SecurityDefense\Tests\TestCase;

final class CredentialStuffingTest extends TestCase
{
    protected function setUp(): void { parent::setUp(); Cache::flush(); config()->set('security-defense.detection.rules.credential_stuffing.threshold', 5); }

    #[DataProvider('accountProvider')]
    public function test_one_ip_targeting_distinct_accounts_is_detected(array $accounts, bool $blocked): void
    {
        $rule = app(CredentialStuffingRule::class); $result = null;
        foreach ($accounts as $account) $result = $rule->evaluate(new SecurityEvent('203.0.113.200', $account, 'LoginFailed'));
        $this->assertSame($blocked, $result !== null);
    }

    #[DataProvider('eventProvider')]
    public function test_stuffing_does_not_count_non_login_events(string $event): void
    {
        $rule = app(CredentialStuffingRule::class); $result = null;
        foreach (range(1, 8) as $n) $result = $rule->evaluate(new SecurityEvent('203.0.113.201', "user{$n}@example.test", $event));
        $this->assertNull($result);
    }

    public static function accountProvider(): array
    {
        return ['under' => [array_map(fn($n) => "user{$n}@example.test", range(1,4)), false], 'exact' => [array_map(fn($n) => "user{$n}@example.test", range(1,5)), true], 'over' => [array_map(fn($n) => "user{$n}@example.test", range(1,8)), true], 'case duplicates' => [['User@Test','user@test','USER@TEST','user@test'], false], 'slow spray' => [array_map(fn($n) => "victim{$n}@example.test", range(1,12)), true]];
    }
    public static function eventProvider(): array { return ['success' => ['LoginSucceeded'], 'otp' => ['OTP_FAILED'], 'logout' => ['Logout'], 'generic' => ['GenericSecurityEvent']]; }
}
