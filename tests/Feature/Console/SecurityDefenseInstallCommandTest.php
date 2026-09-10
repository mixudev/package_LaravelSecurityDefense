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

    /**
     * Fixture token: valid 43-char base64url segment (32 random bytes, unpadded).
     * Kept out of literals so no install-time secret ever ships in the test file.
     */
    private function fixtureToken(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    }

    public function test_dry_run_never_writes_or_prints_token(): void
    {
        $token = $this->fixtureToken();

        $this->artisan('security-defense:install', [
            '--with-opaque-path' => true,
            '--token' => $token,
            '--dry-run' => true,
            '--no-migrate' => true,
            '--no-cache' => true,
        ])->expectsOutputToContain('Dry run')
            ->doesntExpectOutput($token)
            ->assertSuccessful();

        $this->assertFileDoesNotExist(base_path('.env'));
    }

    public function test_explicit_token_written_to_env_only_and_never_printed(): void
    {
        $token = $this->fixtureToken();
        file_put_contents(base_path('.env'), "APP_ENV=testing\nKEEP_ME=yes\n");

        $this->artisan('security-defense:install', [
            '--with-opaque-path' => true,
            '--token' => $token,
            '--no-migrate' => true,
            '--no-cache' => true,
        ])->doesntExpectOutput($token)
            ->assertSuccessful();

        $env = (string) file_get_contents(base_path('.env'));
        $this->assertStringContainsString('APP_ENV=testing', $env);
        $this->assertStringContainsString('KEEP_ME=yes', $env);
        $this->assertStringContainsString('SECURITY_DEFENSE_DASHBOARD_PATH=' . $token, $env);
        $this->assertStringNotContainsString($token, (string) file_get_contents(config_path('security-defense.php')));
    }

    public function test_missing_env_generates_valid_base64url_token_and_keeps_it_secret(): void
    {
        Artisan::call('security-defense:install', [
            '--with-opaque-path' => true,
            '--no-migrate' => true,
            '--no-cache' => true,
        ]);

        $env = (string) file_get_contents(base_path('.env'));
        $this->assertMatchesRegularExpression('/^SECURITY_DEFENSE_DASHBOARD_PATH=[A-Za-z0-9_-]{43,88}$/m', $env);

        preg_match('/^SECURITY_DEFENSE_DASHBOARD_PATH=([A-Za-z0-9_-]+)$/m', $env, $match);
        $this->assertSame(43, strlen($match[1] ?? ''));
        $this->assertStringNotContainsString($match[1], Artisan::output());
    }

    public function test_existing_env_token_is_preserved_when_opaque_enabled(): void
    {
        $token = $this->fixtureToken();
        file_put_contents(base_path('.env'), 'SECURITY_DEFENSE_DASHBOARD_PATH=' . $token . "\nOTHER=1\n");

        $this->artisan('security-defense:install', [
            '--with-opaque-path' => true,
            '--no-migrate' => true,
            '--no-cache' => true,
        ])->doesntExpectOutput($token)
            ->assertSuccessful();

        $env = (string) file_get_contents(base_path('.env'));
        $this->assertStringContainsString('SECURITY_DEFENSE_DASHBOARD_PATH=' . $token, $env);
        $this->assertStringContainsString('OTHER=1', $env);
    }

    public function test_invalid_token_option_is_rejected(): void
    {
        $this->artisan('security-defense:install', [
            '--with-opaque-path' => true,
            '--token' => 'not-a-valid-token',
            '--no-migrate' => true,
            '--no-cache' => true,
        ])->assertFailed();

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

    public function test_with_opaque_path_enables_config_switch_without_storing_token(): void
    {
        $token = $this->fixtureToken();
        file_put_contents(base_path('.env'), 'SECURITY_DEFENSE_DASHBOARD_PATH=' . $token . "
\nOTHER=1\n");

        $this->artisan('security-defense:install', [
            '--with-opaque-path' => true,
            '--no-migrate' => true,
            '--no-cache' => true,
        ])->doesntExpectOutput($token)
            ->assertSuccessful();

        $this->assertTrue(config('security-defense.dashboard.opaque_path.enabled'));
        $this->assertStringNotContainsString($token, (string) file_get_contents(config_path('security-defense-overrides.php') ?? ''));
        $this->assertStringNotContainsString($token, (string) file_get_contents(config_path('security-defense.php')));
    }
}