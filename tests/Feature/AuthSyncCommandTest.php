<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature;

use Mixudev\SecurityDefense\Console\Commands\AuthSyncCommand;
use Mixudev\SecurityDefense\Tests\TestCase;

/**
 * Tests for the auth:sync command (static/dry-run behavior; never executes
 * composer require against a real auth package in the test environment).
 */
class AuthSyncCommandTest extends TestCase
{
    public function test_command_is_registered_in_artisan(): void
    {
        $this->assertTrue($this->app->runningInConsole());
        $this->assertTrue($this->artisan('list')->run() === 0);
    }

    public function test_auth_sync_aborts_when_auth_package_not_installed(): void
    {
        // Auth package is NOT installed in this package's test env — command must
        // fail gracefully with a pointer to authentication:install, no writes.
        $exitCode = $this->artisan('auth:sync')
            ->expectsOutputToContain('belum terpasang')
            ->expectsOutputToContain('authentication:install')
            ->run();

        $this->assertSame(1, $exitCode);
        $this->assertFileDoesNotExist(app_path('Listeners/AuthenticationSecuritySubscriber.php'));
    }

    public function test_auth_event_mapping_has_expected_handlers(): void
    {
        $command = new AuthSyncCommand();
        $reflection = new \ReflectionMethod(AuthSyncCommand::class, 'authEventMapping');
        $events = $reflection->invoke($command);

        $this->assertCount(12, $events);
        $this->assertArrayHasKey('loginFailed', $events);
        $this->assertArrayHasKey('loginSucceeded', $events);
        $this->assertSame('LoginFailed', $events['loginFailed']['eventType']);
        $this->assertSame('OTP_VERIFIED', $events['otpVerified']['eventType']);
    }

    public function test_waf_middleware_injection_into_bootstrap_app(): void
    {
        $tmpBase = sys_get_temp_dir() . '/authsync-waf-' . uniqid();
        $files = new \Illuminate\Filesystem\Filesystem();
        $files->ensureDirectoryExists($tmpBase . '/bootstrap');
        $files->put($tmpBase . '/bootstrap/app.php', "<?php\n\nreturn \\Illuminate\\Foundation\\Application::configure(basePath: dirname(__DIR__))\n    ->withMiddleware(function (\\Illuminate\\Foundation\\Configuration\\Middleware \$middleware) {\n        \$middleware->append(\\Illuminate\\Session\\Middleware\\StartSession::class);\n    })\n    ->create();\n");

        $command = new class extends AuthSyncCommand {
            public string $tmpBase = '';

            protected function bootstrapFile(): string
            {
                return $this->tmpBase . '/bootstrap/app.php';
            }

            protected function kernelFile(): string
            {
                return $this->tmpBase . '/app/Http/Kernel.php';
            }
        };
        $command->tmpBase = $tmpBase;
        $command->setOutput(new \Illuminate\Console\OutputStyle(
            new \Symfony\Component\Console\Input\ArrayInput([]),
            new \Symfony\Component\Console\Output\BufferedOutput()
        ));

        $reflection = new \ReflectionMethod(AuthSyncCommand::class, 'injectWafMiddleware');
        $reflection->invoke($command, $files, false);

        $content = $files->get($tmpBase . '/bootstrap/app.php');
        $this->assertStringContainsString('RequestThreatScanner', $content);
        $this->assertStringContainsString('$middleware->append(', $content);

        $files->deleteDirectory($tmpBase);
    }

    /**
     * Bridge registration must be verified against the LIVE dispatcher.
     *
     * The old logic only grepped AppServiceProvider for the subscriber name,
     * so a Laravel 11+ app discovered via app/Listeners looked "not
     * registered" and auth:sync told the operator to add Event::subscribe() —
     * doubling every handler (SecurityDefense::record() twice per auth event,
     * lockout at half the configured threshold).
     */
    public function test_auto_discovered_subscriber_is_reported_without_manual_hint(): void
    {
        $command = $this->bridgeProbe();

        $this->app['events']->listen(
            \Vendor\LaravelAuthentication\Events\LoginFailed::class,
            'App\\Listeners\\AuthenticationSecuritySubscriber@handleLoginFailed'
        );

        $this->assertSame('auto-discovered', $command->registrationMode());

        $report = $command->registrationReport();
        $this->assertStringContainsString('discovered from app/Listeners', $report);
        $this->assertStringNotContainsString('Register the subscriber in AppServiceProvider', $report);
    }

    public function test_duplicate_bridge_registration_is_detected_and_never_recommends_manual_subscribe(): void
    {
        $command = $this->bridgeProbe();

        // Two registrations on one event = discovery + manual Event::subscribe().
        $this->app['events']->listen(
            \Vendor\LaravelAuthentication\Events\LoginFailed::class,
            'App\\Listeners\\AuthenticationSecuritySubscriber@handleLoginFailed'
        );
        $this->app['events']->listen(
            \Vendor\LaravelAuthentication\Events\LoginFailed::class,
            'App\\Listeners\\AuthenticationSecuritySubscriber@handleLoginFailed'
        );

        $this->assertSame('duplicate', $command->registrationMode());

        $report = $command->registrationReport();
        $this->assertStringContainsString('registered more than once', $report);
        $this->assertStringNotContainsString('Register the subscriber in AppServiceProvider', $report);
    }

    public function test_unregistered_subscriber_reports_next_step_not_registered(): void
    {
        $command = $this->bridgeProbe();

        $this->assertSame('none', $command->registrationMode());

        $report = $command->registrationReport();
        $this->assertStringContainsString('[NEXT]', $report);
        $this->assertStringNotContainsString('already registered', $report);
    }

    public function test_generated_subscriber_body_is_valid_php(): void
    {
        $command = new AuthSyncCommand();
        $reflection = new \ReflectionMethod(AuthSyncCommand::class, 'authEventMapping');
        $events = $reflection->invoke($command);
        $bodyReflection = new \ReflectionMethod(AuthSyncCommand::class, 'buildSubscriberBody');
        $body = $bodyReflection->invoke($command, $events);

        // Lint the generated file via a temp file
        $tmp = tempnam(sys_get_temp_dir(), 'authsync') . '.php';
        file_put_contents($tmp, $body);
        $output = [];
        $exitCode = 0;
        exec(PHP_BINARY . ' -l ' . escapeshellarg($tmp) . ' 2>&1', $output, $exitCode);
        @unlink($tmp);

        $this->assertSame(0, $exitCode, implode("\n", $output));
        $this->assertStringContainsString('class AuthenticationSecuritySubscriber', $body);
        $this->assertStringContainsString('handleLoginSucceeded', $body);
    }

    /**
     * Command probe exposing the protected registration report with output
     * captured in memory (no console side effects).
     *
     * @return AuthSyncCommand&object{
     *     registrationMode(): string,
     *     registrationReport(): string
     * }
     */
    private function bridgeProbe(): object
    {
        $command = new class extends AuthSyncCommand {
            /** @var list<string> */
            public array $captured = [];

            public function registrationMode(): string
            {
                return $this->bridgeRegistrationMode();
            }

            public function registrationReport(): string
            {
                $this->captured = [];

                $this->reportBridgeRegistration();

                return implode("\n", $this->captured);
            }

            public function line($string, $style = null, $verbosity = null)
            {
                $this->captured[] = (string) $string;
            }

            public function error($string, $verbosity = null)
            {
                $this->captured[] = (string) $string;
            }
        };

        $command->setLaravel($this->app);

        return $command;
    }
}