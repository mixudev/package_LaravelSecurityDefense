<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Unit;

use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Repository;
use Illuminate\Contracts\Cache\LockProvider;
use Mixudev\SecurityDefense\DTO\SecurityEvent;
use Mixudev\SecurityDefense\Rules\ImpossibleTravelRule;
use Mixudev\SecurityDefense\Services\IpQuarantineService;
use Mixudev\SecurityDefense\Support\CacheLock;
use Mixudev\SecurityDefense\Support\DashboardCapability;
use Mixudev\SecurityDefense\Tests\TestCase;

/**
 * Regression guard for the class of bug where method_exists($cache, 'lock')
 * is false against the Repository wrapper, so every lock written behind that
 * guard silently never runs.
 *
 * If the old guard is reintroduced anywhere in the package, this test must fail
 * loudly instead of the protection quietly disappearing.
 */
final class LockGuardRegressionTest extends TestCase
{
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);
        $app['config']->set('app.key', 'base64:7VzK9gG2e+x8UfXoN9uC7x/2j6yD8Hw0Z1A2B3C4D5E=');
        $app['config']->set('security-defense.detection.rules.impossible_travel', ['enabled' => true]);
    }

    /**
     * The root cause, asserted directly so the whole class of bug is named.
     */
    public function test_repository_wrapper_never_declares_lock_but_the_store_does(): void
    {
        $cache = new Repository(new ArrayStore());

        self::assertFalse(
            method_exists($cache, 'lock'),
            'If this ever becomes true, the CacheLock indirection is no longer required.'
        );
        self::assertInstanceOf(LockProvider::class, $cache->getStore());
    }

    /**
     * @dataProvider lockSiteProvider
     */
    public function test_no_source_file_uses_the_broken_method_exists_lock_guard(string $relativePath): void
    {
        $path = dirname(__DIR__, 2) . '/' . $relativePath;
        self::assertFileExists($path);

        $source = (string) file_get_contents($path);

        foreach (['$cache', '$this->cache'] as $subject) {
            $needle = 'method_exists(' . $subject . ", 'lock')";

            self::assertStringNotContainsString(
                $needle,
                $source,
                $relativePath . ' still guards a cache lock with ' . $needle
                . ', which is always false against the Repository wrapper. Use CacheLock::run() instead.'
            );
        }
    }

    /** @return array<string, array{0: string}> */
    public static function lockSiteProvider(): array
    {
        return [
            'dashboard capability consume' => ['src/Support/DashboardCapability.php'],
            'ip quarantine mutation' => ['src/Services/IpQuarantineService.php'],
            'impossible travel rule' => ['src/Rules/ImpossibleTravelRule.php'],
            'experience memory' => ['src/Epistemic/Memory/ExperienceMemory.php'],
            'alert dispatcher rate limit' => ['src/Services/AlertDispatcher.php'],
            'dashboard otp service' => ['src/Services/DashboardOtpService.php'],
        ];
    }

    public function test_dashboard_capability_consume_remains_one_time(): void
    {
        $capability = new DashboardCapability(new Repository(new ArrayStore()));
        $token = $capability->issue('session-race');

        // A second consume of the SAME token must fail. This is the property the
        // lock guarantees under concurrency; sequentially it must hold too, which
        // is what makes the lock fix observable.
        self::assertMatchesRegularExpression(
            '/^[A-Za-z0-9_-]{64}$/',
            (string) $capability->consume($token, 'session-race')
        );
        self::assertNull($capability->consume($token, 'session-race'));
    }

    public function test_cache_lock_releases_so_a_second_acquire_does_not_stall(): void
    {
        $cache = new Repository(new ArrayStore());

        self::assertSame('a', CacheLock::run($cache, 'k', 5, static fn (): string => 'a'));
        // Would block for the full timeout (then throw) if the first lock leaked.
        self::assertSame('b', CacheLock::run($cache, 'k', 5, static fn (): string => 'b'));
    }

    public function test_quarantine_mutation_still_works_through_the_new_guard(): void
    {
        $quarantine = new IpQuarantineService(new Repository(new ArrayStore()));

        self::assertTrue($quarantine->jail('203.0.113.200', 60, 'unit test'));
        self::assertTrue($quarantine->isQuarantined('203.0.113.200'));

        $quarantine->pardon('203.0.113.200');
        self::assertFalse($quarantine->isQuarantined('203.0.113.200'));
    }

    public function test_impossible_travel_still_evaluates_through_the_new_guard(): void
    {
        $rule = new ImpossibleTravelRule(new Repository(new ArrayStore()));

        // Baseline establishes the location; no threat on the first sighting.
        self::assertNull($rule->evaluate($this->travelEvent('user-1', '198.51.100.1', 'ID')));

        // Country change well inside the 10-minute window must still fire.
        $threat = $rule->evaluate($this->travelEvent('user-1', '8.8.8.8', 'US'));
        self::assertNotNull($threat, 'Impossible travel must still fire on a fast country change.');
        self::assertSame('impossible_travel', $threat->threatType);
    }

    private function travelEvent(string $identifier, string $ip, string $country): SecurityEvent
    {
        return new SecurityEvent(
            ip: $ip,
            identifier: $identifier,
            eventType: 'LoginSucceeded',
            metadata: ['country' => $country],
        );
    }
}
