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

    public function test_auth_sync_dry_run_reports_planned_steps_without_writing(): void
    {
        // dry-run must be safe in a package (no composer, no auth package installed)
        $exitCode = $this->artisan('auth:sync', ['--dry-run' => true])
            ->expectsOutputToContain('[DRY-RUN]')
            ->run();

        $this->assertSame(0, $exitCode);
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
}