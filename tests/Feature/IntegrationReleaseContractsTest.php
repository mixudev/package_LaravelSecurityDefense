<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature;

use Illuminate\Contracts\Cache\Repository;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Schema;
use Mixudev\SecurityDefense\Contracts\AlertDeduplicatorInterface;
use Mixudev\SecurityDefense\Epistemic\Contracts\ExperienceMemoryInterface;
use Mixudev\SecurityDefense\Epistemic\Memory\ExperienceMemory;
use Mixudev\SecurityDefense\Http\Middleware\EnsureLocalAccess;
use Mixudev\SecurityDefense\Services\AlertDispatcher;
use Mixudev\SecurityDefense\Services\IpQuarantineService;
use Mixudev\SecurityDefense\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

final class IntegrationReleaseContractsTest extends TestCase
{
    #[Test]
    public function package_migrations_create_and_drop_all_tables_on_sqlite(): void
    {
        foreach (['security_alerts', 'security_quarantines', 'security_data_audits', 'epistemic_threat_patterns'] as $table) {
            self::assertTrue(Schema::hasTable($table), $table . ' missing after up');
        }

        $this->artisan('migrate:rollback')->assertExitCode(0);

        foreach (['security_alerts', 'security_quarantines', 'security_data_audits', 'epistemic_threat_patterns'] as $table) {
            self::assertFalse(Schema::hasTable($table), $table . ' remains after down');
        }
    }

    #[Test]
    public function provider_merges_defaults_and_honors_cached_config(): void
    {
        self::assertSame('security_defense:', config('security-defense.cache_prefix'));
        self::assertTrue(config('security-defense.enabled'));
        self::assertSame('array', config('cache.default'));
        self::assertInstanceOf(AlertDispatcher::class, app(AlertDispatcher::class));
    }

    #[Test]
    public function cache_store_setting_is_used_by_dispatcher_and_quarantine(): void
    {
        config(['security-defense.cache_store' => 'dedicated']);
        config(['cache.stores.dedicated' => ['driver' => 'array']]);
        Cache::store('dedicated')->flush();
        config(['security-defense.hardening.alert_rate_limit.max_alerts_per_minute' => 1]);

        $deduplicator = new class implements AlertDeduplicatorInterface {
            public function shouldAlert(\Mixudev\SecurityDefense\DTO\SecurityThreat $threat): bool { return true; }
            public function record(\Mixudev\SecurityDefense\DTO\SecurityThreat $threat): void {}
            public function forget(string $fingerprint): void {}
        };
        $dispatcher = new AlertDispatcher($deduplicator);
        $reflection = new \ReflectionMethod($dispatcher, 'acquireRateLimitSlot');
        $reflection->setAccessible(true);
        self::assertTrue($reflection->invoke($dispatcher));
        self::assertSame(1, Cache::store('dedicated')->get('security_defense:rate_limit:alerts_per_minute'));
        self::assertNull(Cache::store('array')->get('security_defense:rate_limit:alerts_per_minute'));

        $quarantine = app(IpQuarantineService::class);
        self::assertTrue($quarantine->jail('203.0.113.10', 60, 'test'));
        self::assertTrue($quarantine->isQuarantined('203.0.113.10'));
    }

    #[Test]
    public function experience_memory_uses_configured_cache_store(): void
    {
        config(['security-defense.cache_store' => 'dedicated']);
        config(['cache.stores.dedicated' => ['driver' => 'array']]);
        $memory = app(ExperienceMemoryInterface::class);
        self::assertInstanceOf(ExperienceMemory::class, $memory);
        $property = new \ReflectionProperty($memory, 'cache');
        $property->setAccessible(true);
        self::assertSame(get_class(Cache::store('dedicated')), get_class($property->getValue($memory)));
    }

    #[Test]
    public function provider_bindings_are_available_only_when_epistemic_is_enabled(): void
    {
        config(['security-defense.epistemic.enabled' => false]);
        $manager = app(\Mixudev\SecurityDefense\Services\SecurityDefenseManager::class);
        $property = new \ReflectionProperty($manager, 'epistemicAnalyzer');
        $property->setAccessible(true);
        self::assertNull($property->getValue($manager));

        config(['security-defense.epistemic.enabled' => true]);
        self::assertNotNull(app(\Mixudev\SecurityDefense\Epistemic\EpistemicAnalyzer::class));
    }

    #[Test]
    public function waf_middleware_requires_explicit_host_registration(): void
    {
        self::assertTrue(class_exists(\Mixudev\SecurityDefense\Middleware\RequestThreatScanner::class));
        self::assertTrue(class_exists(EnsureLocalAccess::class));
        $router = app('router');
        $middleware = $router->getMiddleware();
        self::assertArrayNotHasKey('security-defense', $middleware);
    }
}
