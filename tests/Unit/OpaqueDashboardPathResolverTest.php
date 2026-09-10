<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Unit;

use Mixudev\SecurityDefense\Support\OpaqueDashboardPathResolver;
use PHPUnit\Framework\TestCase;

class OpaqueDashboardPathResolverTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        putenv('SECURITY_DEFENSE_DASHBOARD_PATH');
    }

    protected function tearDown(): void
    {
        putenv('SECURITY_DEFENSE_DASHBOARD_PATH');
        parent::tearDown();
    }

    public function test_missing_or_malformed_secret_fails_closed_to_unreachable_path(): void
    {
        self::assertNull(OpaqueDashboardPathResolver::token());
        self::assertSame('__opaque_dashboard_unreachable__', OpaqueDashboardPathResolver::resolvePath(true));

        putenv('SECURITY_DEFENSE_DASHBOARD_PATH=bad/token');
        self::assertNull(OpaqueDashboardPathResolver::token());
        self::assertSame('__opaque_dashboard_unreachable__', OpaqueDashboardPathResolver::resolvePath(true));
    }

    public function test_valid_base64url_secret_resolves_without_padding_or_separator(): void
    {
        $token = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
        putenv('SECURITY_DEFENSE_DASHBOARD_PATH=' . $token);

        self::assertSame($token, OpaqueDashboardPathResolver::token());
        self::assertSame($token, OpaqueDashboardPathResolver::resolvePath(true));
        self::assertStringNotContainsString('/', $token);
        self::assertStringNotContainsString('=', $token);
    }

    public function test_disabled_mode_preserves_configured_path(): void
    {
        self::assertSame('security-defense', OpaqueDashboardPathResolver::resolvePath(false));
    }
}