<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature\Console;

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Mixudev\SecurityDefense\Tests\TestCase;

class SecurityDefenseInstallCommandTest extends TestCase
{
    private string $originalConfig;
    private ?string $originalEnv;

    protected function setUp(): void
    {
        parent::setUp();

        $this->originalConfig = (string) file_get_contents(config_path('security-defense.php'));
        $this->originalEnv = is_file(base_path('.env')) ? (string) file_get_contents(base_path('.env')) : null;
        @unlink(base_path('.env'));
    }

    protected function tearDown(): void
    {
        Artisan::call('config:clear');
        Artisan::call('route:clear');
        @unlink(config_path('security-defense-overrides.php'));
        file_put_contents(config_path('security-defense.php'), $this->originalConfig);
        if ($this->originalEnv === null) {
            @unlink(base_path('.env'));
        } else {
            file_put_contents(base_path('.env'), $this->originalEnv);
        }
        parent::tearDown();
    }

    public function test_dry_run_never_changes_files(): void
    {
        $this->artisan('security-defense:install', [
            '--with-opaque-path' => true,
            '--dry-run' => true,
            '--no-migrate' => true,
            '--no-cache' => true,
        ])->expectsOutputToContain('Dry run')
            ->assertSuccessful();

        $this->assertFileDoesNotExist(base_path('.env'));
    }

    public function test_existing_published_config_not_overwritten_without_force(): void
    {
        file_put_contents(config_path('security-defense.php'), "<?php return ['sentinel' => true];\n");

        $this->artisan('security-defense:install', [
            '--no-migrate' => true,
            '--no-cache' => true,
        ])->assertSuccessful();

        $this->assertStringContainsString('sentinel', (string) file_get_contents(config_path('security-defense.php')));
    }

    public function test_force_overwrites_published_config(): void
    {
        file_put_contents(config_path('security-defense.php'), "<?php return ['sentinel' => true];\n");

        $this->artisan('security-defense:install', [
            '--force' => true,
            '--no-migrate' => true,
            '--no-cache' => true,
        ])->assertSuccessful();

        $this->assertStringNotContainsString('sentinel', (string) file_get_contents(config_path('security-defense.php')));
    }

    public function test_default_run_migrates_database(): void
    {
        Schema::dropIfExists('security_alerts');
        DB::table('migrations')->where('migration', 'like', '%security%')->delete();

        Artisan::call('security-defense:install', [
            '--no-cache' => true,
        ]);

        $this->assertTrue(Schema::hasTable('security_alerts'));
    }

    public function test_default_run_rebuilds_caches(): void
    {
        $this->artisan('security-defense:install', [
            '--force' => true,
        ])->assertSuccessful();
    }

    public function test_with_opaque_path_enables_config_switch_without_env_token(): void
    {
        file_put_contents(base_path('.env'), "APP_ENV=testing\nOTHER=1\n");

        $this->artisan('security-defense:install', [
            '--with-opaque-path' => true,
            '--no-migrate' => true,
            '--no-cache' => true,
        ])->assertSuccessful();

        $this->assertTrue(config('security-defense.dashboard.opaque_path.enabled'));
        $envContents = (string) file_get_contents(base_path('.env'));
        $this->assertStringNotContainsString('SECURITY_DEFENSE_DASHBOARD_PATH', $envContents);
        $overrides = (string) (is_file(config_path('security-defense-overrides.php')) ? file_get_contents(config_path('security-defense-overrides.php')) : '');
        $this->assertStringNotContainsString('SECURITY_DEFENSE_DASHBOARD_PATH', $overrides);
    }
}