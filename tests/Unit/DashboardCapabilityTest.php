<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Unit;

use Illuminate\Support\Facades\Cache;
use Mixudev\SecurityDefense\Support\DashboardCapability;
use Mixudev\SecurityDefense\Tests\TestCase;

final class DashboardCapabilityTest extends TestCase
{
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);
        $app['config']->set('app.key', 'base64:7VzK9gG2e+x8UfXoN9uC7x/2j6yD8Hw0Z1A2B3C4D5E=');
        $app['config']->set('security-defense.dashboard.opaque_path.ttl_seconds', 60);
    }

    public function test_capability_is_encrypted_hmac_signed_session_bound_and_one_time(): void
    {
        $capability = app(DashboardCapability::class);
        $url = $capability->issue('session-a');

        self::assertFalse(str_contains($url, 'security-defense.dashboard.entry'));
        self::assertNull($capability->consume($url, 'session-b'));
        self::assertSame($capability->sessionPath('session-a'), $capability->consume($url, 'session-a'));
        self::assertNull($capability->consume($url, 'session-a'));
    }

    public function test_tampered_capability_is_rejected(): void
    {
        $capability = app(DashboardCapability::class);
        $url = $capability->issue('session-a');
        $tampered = substr($url, 0, -1) . (substr($url, -1) === 'a' ? 'b' : 'a');

        self::assertNull($capability->consume($tampered, 'session-a'));
    }

    public function test_session_path_is_deterministic_but_bound_to_session(): void
    {
        $capability = app(DashboardCapability::class);

        self::assertSame($capability->sessionPath('a'), $capability->sessionPath('a'));
        self::assertNotSame($capability->sessionPath('a'), $capability->sessionPath('b'));
        self::assertTrue($capability->isSessionPath($capability->sessionPath('a'), 'a'));
        self::assertFalse($capability->isSessionPath($capability->sessionPath('a'), 'b'));
    }

    public function test_dedicated_security_defense_key_overrides_app_key(): void
    {
        $capability = app(DashboardCapability::class);
        $url1 = $capability->issue('session-x');

        // Set dedicated key — capability issued under dedicated key must reject url1.
        config()->set('security-defense.dashboard.key', 'base64:' . base64_encode(random_bytes(32)));
        self::assertNull($capability->consume($url1, 'session-x'));

        // Issue under dedicated key and consume successfully.
        $url2 = $capability->issue('session-x');
        self::assertSame($capability->sessionPath('session-x'), $capability->consume($url2, 'session-x'));
    }

    public function test_capability_and_session_path_fit_route_pattern(): void
    {
        $capability = app(DashboardCapability::class);
        $url = $capability->issue('session-route');
        $sessionPath = $capability->sessionPath('session-route');

        // Capability URL + session path must both match ROUTE_PATTERN length
        // range so ordinary short paths (e.g. /login, /dsafsafaf) never match.
        $supports = static fn (string $v): bool => preg_match('/^' . DashboardCapability::ROUTE_PATTERN . '$/', $v) === 1;

        self::assertTrue($supports($url), 'Capability URL must match ROUTE_PATTERN');
        self::assertTrue($supports($sessionPath), 'Session path must match ROUTE_PATTERN');
        self::assertGreaterThanOrEqual(64, strlen($url));
        self::assertLessThanOrEqual(160, strlen($url));
        self::assertSame(64, strlen($sessionPath));

        // Short random URL must NOT match the route pattern (404 instead of 403).
        self::assertFalse($supports('dsafsafaf'));
        self::assertFalse($supports('security-defense-test'));
        self::assertFalse($supports('login'));
    }
}
