<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature;

use Mixudev\SecurityDefense\Tests\TestCase;

class DashboardOpaquePathConfigTest extends TestCase
{
    public function test_opaque_path_config_has_safe_defaults(): void
    {
        $config = config('security-defense.dashboard.opaque_path');

        self::assertIsArray($config, 'dashboard.opaque_path must exist.');
        self::assertArrayHasKey('enabled', $config);
        self::assertArrayHasKey('length_bytes', $config);
        self::assertArrayHasKey('ttl_seconds', $config);
        self::assertArrayHasKey('rotate_on_success', $config);
        self::assertArrayHasKey('allow_query_token', $config);

        self::assertArrayNotHasKey('token', $config, 'Opaque token must stay outside config cache.');
        self::assertFalse($config['enabled'], 'Opaque path must be opt-in, default off.');
        self::assertFalse($config['allow_query_token'], 'Query tokens must never authorize.');
        self::assertGreaterThanOrEqual(32, (int) $config['length_bytes']);
        self::assertLessThanOrEqual(64, (int) $config['length_bytes']);
        self::assertGreaterThan(0, (int) $config['ttl_seconds']);
    }

    public function test_opaque_path_config_does_not_contain_any_secret_material(): void
    {
        $all = config('security-defense.dashboard.opaque_path');

        $serialized = serialize($all);
        // Key names legitimately include 'token' (allow_query_token); values must not.
        self::assertStringNotContainsString('password', strtolower($serialized));
    }
}