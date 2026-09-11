<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Unit;

use Mixudev\SecurityDefense\Support\OpaqueRouteAliases;
use PHPUnit\Framework\TestCase;

final class OpaqueRouteAliasesTest extends TestCase
{
    public function test_aliases_exist_for_all_dashboard_routes(): void
    {
        foreach ([
            'security-defense.dashboard',
            'security-defense.data-audits',
            'security-defense.sessions',
            'security-defense.epistemic',
            'security-defense.epistemic.feedback',
            'security-defense.test-channel',
            'security-defense.alerts.acknowledge',
            'security-defense.alerts.resolve',
            'security-defense.quarantine.pardon',
            'security-defense.quarantine.whitelist',
            'security-defense.live-events',
            'security-defense.toggle-setting',
        ] as $route) {
            $path = OpaqueRouteAliases::path($route);
            self::assertNotSame('', $path);
            self::assertStringNotContainsString('sessions', $path);
            self::assertStringNotContainsString('audits', $path);
            self::assertStringNotContainsString('epistemic', $path);
            self::assertStringNotContainsString('live-events', $path);
            self::assertStringNotContainsString('quarantine', $path);
            self::assertStringNotContainsString('toggle', $path);
        }
    }

    public function test_aliases_are_unique_and_stable(): void
    {
        $paths = [];
        foreach ([
            'security-defense.dashboard',
            'security-defense.data-audits',
            'security-defense.sessions',
            'security-defense.epistemic',
            'security-defense.live-events',
            'security-defense.test-channel',
            'security-defense.toggle-setting',
        ] as $route) {
            $paths[$route] = OpaqueRouteAliases::path($route);
        }

        self::assertSame(count($paths), count(array_unique($paths)));

        // Stability: a second resolution pass yields identical mapping.
        $again = [];
        foreach (array_keys($paths) as $route) {
            $again[$route] = OpaqueRouteAliases::path($route);
        }
        self::assertSame($paths, $again);
    }

    public function test_unknown_route_throws(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        OpaqueRouteAliases::path('security-defense.does-not-exist');
    }
}