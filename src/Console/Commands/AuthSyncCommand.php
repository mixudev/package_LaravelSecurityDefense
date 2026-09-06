<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Filesystem\Filesystem;

/**
 * One-command integration between mixudev/security-defense and
 * mixudev/laravel-authentication: installs the auth package, publishes its
 * assets, injects the WAF middleware, and wires the event-subscriber bridge
 * so every auth domain event (login failed/succeeded, lockout, 2FA, device,
 * password, session) flows into the SIEM/defense engine automatically.
 */
class AuthSyncCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'auth:sync
                            {--force : Overwrite existing published auth files and bridge}
                            {--dry-run : Show the planned steps without writing anything}
                            {--composer= : Composer binary/command to use (default: composer)}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Install mixudev/laravel-authentication, publish assets, and wire the security-defense event bridge automatically';

    public function handle(Filesystem $filesystem): int
    {
        $dryRun = (bool) $this->option('dry-run');
        $force = (bool) $this->option('force');
        $composer = is_string($this->option('composer')) ? $this->option('composer') : 'composer';

        if (! $this->authPackageInstalled()) {
            if ($dryRun) {
                $this->line('  [DRY-RUN] Would run: ' . $composer . ' require mixudev/laravel-authentication');
            } else {
                $this->info('[1/6] Installing mixudev/laravel-authentication via Composer...');

                $result = $this->runProcess([$composer, 'require', 'mixudev/laravel-authentication', '--no-interaction']);
                if ($result !== 0) {
                    $this->error('Composer install failed. Run it manually and retry auth:sync.');
                    $this->line('  Manual: ' . $composer . ' require mixudev/laravel-authentication');

                    return self::FAILURE;
                }
            }
        } else {
            $this->line('  [OK] mixudev/laravel-authentication already installed.');
        }

        $steps = [
            'vendor:publish --tag=authentication-config' => 'Publish auth configuration to config/authentication.php',
            'vendor:publish --tag=authentication-migrations' => 'Publish auth migrations to database/migrations/',
        ];

        foreach ($steps as $command => $label) {
            $this->line($dryRun ? "  [DRY-RUN] Would run: php artisan {$command} --force" : "  → {$label}");
            if (! $dryRun) {
                $this->call('vendor:publish', [
                    '--tag' => str_replace('vendor:publish --tag=', '', $command),
                    '--force' => $force,
                ]);
            }
        }

        // WAF middleware injection
        $this->injectWafMiddleware($filesystem, $dryRun);

        // Event bridge subscriber
        $this->createBridgeSubscriber($filesystem, $dryRun);

        // Auth event mapping (used for both dry-run report and registration check)
        $events = $this->authEventMapping();

        if ($dryRun) {
            $this->line('  [DRY-RUN] Would register ' . count($events) . ' auth event handlers via AppServiceProvider::subscribe().');

            return self::SUCCESS;
        }

        if (! $this->isBridgeRegistered()) {
            $this->line('  [NEXT] Register the subscriber in AppServiceProvider::boot():');
            $this->line('    Event::subscribe(\\App\\Listeners\\AuthenticationSecuritySubscriber::class);');
        } else {
            $this->line('  [OK] Bridge subscriber already registered.');
        }

        $this->newLine();
        $this->info('[DONE] auth:sync completed. Subscribe the bridge, then run: php artisan migrate');

        return self::SUCCESS;
    }

    /**
     * Build the bridge subscriber file content based on the mapped auth events.
     *
     * @param array<string, array{event: string, eventType: string, fields: array<string, string>}> $events
     */
    protected function buildSubscriberBody(array $events): string
    {
        $methodBodies = [];
        $handlers = [];

        foreach ($events as $key => $mapping) {
            $eventClass = $mapping['event'];
            $handler = $this->subscriberMethodName($key);
            $method = $this->buildHandlerMethod($eventClass, $key, $mapping['eventType'], $mapping['fields']);
            if ($method !== null) {
                $methodBodies[] = $method;
                $handlers[] = "            {$eventClass}::class => '{$handler}',";
            }
        }

        $subscribeMap = implode("\n", $handlers);
        $methods = implode("\n", $methodBodies);

        return <<<PHP
<?php

declare(strict_types=1);

namespace App\\Listeners;

use Illuminate\\Events\\Dispatcher;
use Mixudev\\SecurityDefense\\Support\\Facades\\SecurityDefense;

class AuthenticationSecuritySubscriber
{
{$methods}
    public function subscribe(Dispatcher \$events): array
    {
        return [
{$subscribeMap}
        ];
    }
}
PHP;
    }

    /**
     * Build a single handler method body for an auth event.
     *
     * @param array<string, string> $fields
     */
    protected function buildHandlerMethod(string $eventClass, string $key, string $eventType, array $fields): ?string
    {
        $identifier = (string) ($fields['identifier'] ?? '');
        $metadata = (string) ($fields['metadata'] ?? '');

        return <<<PHP

    public function {$this->subscriberMethodName($key)}({$eventClass} \${$key}): void
    {
        SecurityDefense::record([
            'ip' => \${$key}->context->ipAddress,
            'identifier' => {$identifier},
            'eventType' => '{$eventType}',
            'userAgent' => \${$key}->context->userAgent,
            'metadata' => [
                {$metadata}
            ],
        ]);
    }
PHP;
    }

    protected function subscriberMethodName(string $key): string
    {
        return 'handle' . ucfirst($key);
    }

    /**
     * Auth event => SecurityDefense::record() mapping (eventType + field accessors).
     *
     * @return array<string, array{event: string, eventType: string, fields: array<string, string>}>
     */
    protected function authEventMapping(): array
    {
        return [
            'loginFailed' => [
                'event' => \Vendor\LaravelAuthentication\Events\LoginFailed::class,
                'eventType' => 'LoginFailed',
                'fields' => [
                    'identifier' => '$event->identifier',
                    'metadata' => "'reason' => \$event->reason,\n                'user_id' => \$event->user?->getAuthIdentifier()",
                ],
            ],
            'loginSucceeded' => [
                'event' => \Vendor\LaravelAuthentication\Events\LoginSucceeded::class,
                'eventType' => 'LoginSucceeded',
                'fields' => [
                    'identifier' => "(string) (\$event->user->email ?? \$event->user->username ?? \$event->user->getAuthIdentifier())",
                    'metadata' => "'strategy' => \$event->strategy,\n                'user_id' => \$event->user->getAuthIdentifier()",
                ],
            ],
            'accountLocked' => [
                'event' => \Vendor\LaravelAuthentication\Events\AccountLocked::class,
                'eventType' => 'AccountLocked',
                'fields' => [
                    'identifier' => "(string) (\$event->user->email ?? \$event->user->username ?? \$event->user->getAuthIdentifier())",
                    'metadata' => "'lockout_duration_minutes' => \$event->lockoutDurationMinutes,\n                'user_id' => \$event->user->getAuthIdentifier()",
                ],
            ],
            'newDeviceLoginDetected' => [
                'event' => \Vendor\LaravelAuthentication\Events\NewDeviceLoginDetected::class,
                'eventType' => 'NewDeviceLoginDetected',
                'fields' => [
                    'identifier' => "(string) (\$event->user->email ?? \$event->user->username ?? \$event->user->getAuthIdentifier())",
                    'metadata' => "'device_id' => \$event->device->id,\n                'user_id' => \$event->user->getAuthIdentifier()",
                ],
            ],
            'otpVerified' => [
                'event' => \Vendor\LaravelAuthentication\Events\OtpVerified::class,
                'eventType' => 'OTP_VERIFIED',
                'fields' => [
                    'identifier' => '$event->identifier',
                    'metadata' => "'user_id' => \$event->user->getAuthIdentifier()",
                ],
            ],
            'passwordChanged' => [
                'event' => \Vendor\LaravelAuthentication\Events\PasswordChanged::class,
                'eventType' => 'PasswordChanged',
                'fields' => [
                    'identifier' => "(string) (\$event->user->email ?? \$event->user->username ?? \$event->user->getAuthIdentifier())",
                    'metadata' => "'user_id' => \$event->user->getAuthIdentifier()",
                ],
            ],
            'sessionRevoked' => [
                'event' => \Vendor\LaravelAuthentication\Events\SessionRevoked::class,
                'eventType' => 'SessionRevoked',
                'fields' => [
                    'identifier' => "(string) (\$event->user?->email ?? \$event->user?->username ?? (\$event->user ? \$event->user->getAuthIdentifier() : 'anonymous'))",
                    'metadata' => "'session_id' => \$event->sessionId,\n                'user_id' => \$event->user?->getAuthIdentifier()",
                ],
            ],
            'logoutPerformed' => [
                'event' => \Vendor\LaravelAuthentication\Events\LogoutPerformed::class,
                'eventType' => 'LogoutPerformed',
                'fields' => [
                    'identifier' => "(string) (\$event->user?->email ?? \$event->user?->username ?? (\$event->user ? \$event->user->getAuthIdentifier() : 'anonymous'))",
                    'metadata' => "'user_id' => \$event->user?->getAuthIdentifier()",
                ],
            ],
            'userRegistered' => [
                'event' => \Vendor\LaravelAuthentication\Events\UserRegistered::class,
                'eventType' => 'UserRegistered',
                'fields' => [
                    'identifier' => "(string) (\$event->user->email ?? \$event->user->username ?? \$event->user->getAuthIdentifier())",
                    'metadata' => "'user_id' => \$event->user->getAuthIdentifier()",
                ],
            ],
            'passwordResetRequested' => [
                'event' => \Vendor\LaravelAuthentication\Events\PasswordResetRequested::class,
                'eventType' => 'PasswordResetRequested',
                'fields' => [
                    'identifier' => "(string) (\$event->user?->email ?? \$event->user?->username ?? (\$event->user ? \$event->user->getAuthIdentifier() : 'anonymous'))",
                    'metadata' => "'user_id' => \$event->user?->getAuthIdentifier()",
                ],
            ],
            'passwordResetCompleted' => [
                'event' => \Vendor\LaravelAuthentication\Events\PasswordResetCompleted::class,
                'eventType' => 'PasswordResetCompleted',
                'fields' => [
                    'identifier' => "(string) (\$event->user->email ?? \$event->user->username ?? \$event->user->getAuthIdentifier())",
                    'metadata' => "'user_id' => \$event->user->getAuthIdentifier()",
                ],
            ],
            'emailVerified' => [
                'event' => \Vendor\LaravelAuthentication\Events\EmailVerified::class,
                'eventType' => 'EmailVerified',
                'fields' => [
                    'identifier' => "(string) (\$event->user->email ?? \$event->user->username ?? \$event->user->getAuthIdentifier())",
                    'metadata' => "'user_id' => \$event->user->getAuthIdentifier()",
                ],
            ],
        ];
    }

    /**
     * Whether the auth package is installed in the host application.
     */
    protected function authPackageInstalled(): bool
    {
        return class_exists(\Vendor\LaravelAuthentication\Providers\AuthenticationServiceProvider::class);
    }

    /**
     * Run an external process, returning its exit code.
     *
     * @param array<int, string> $command
     */
    protected function runProcess(array $command): int
    {
        $output = [];
        $exitCode = 0;

        exec(implode(' ', array_map('escapeshellarg', $command)) . ' 2>&1', $output, $exitCode);

        foreach ($output as $line) {
            $this->line($line);
        }

        return $exitCode;
    }

    /**
     * Inject the WAF middleware into the host application.
     * Laravel 11+ uses bootstrap/app.php; Laravel 10 uses app/Http/Kernel.php.
     */
    protected function injectWafMiddleware(Filesystem $filesystem, bool $dryRun): void
    {
        $appBootstrap = base_path('bootstrap/app.php');
        $kernelPath = app_path('Http/Kernel.php');

        if ($filesystem->exists($appBootstrap)) {
            $content = $filesystem->get($appBootstrap);
            $needle = 'Mixudev\SecurityDefense\Middleware\RequestThreatScanner';

            if (str_contains($content, $needle)) {
                $this->line('  [OK] WAF middleware already registered in bootstrap/app.php');

                return;
            }

            if (str_contains($content, '$middleware->append(')) {
                $injection = $dryRun
                    ? '  [DRY-RUN] Would append RequestThreatScanner to bootstrap/app.php'
                    : '';
                $this->line($injection ?: '  → Injecting WAF middleware into bootstrap/app.php');

                if ($dryRun) {
                    return;
                }

                $content = str_replace(
                    '$middleware->append(',
                    '$middleware->append(\\Mixudev\\SecurityDefense\\Middleware\\RequestThreatScanner::class);' . PHP_EOL . '        $middleware->append(',
                    $content
                );
                $filesystem->put($appBootstrap, $content);

                return;
            }

            $this->warn('  [WARN] bootstrap/app.php found but no $middleware->append( pattern. Add RequestThreatScanner manually.');
        } elseif ($filesystem->exists($kernelPath)) {
            $content = $filesystem->get($kernelPath);
            $needle = 'Mixudev\SecurityDefense\Middleware\RequestThreatScanner';

            if (str_contains($content, $needle)) {
                $this->line('  [OK] WAF middleware already registered in app/Http/Kernel.php');

                return;
            }

            if ($dryRun) {
                $this->line('  [DRY-RUN] Would add RequestThreatScanner to app/Http/Kernel.php $middleware');

                return;
            }

            $content = str_replace(
                'protected $middleware = [',
                'protected $middleware = [' . PHP_EOL . '        \\Mixudev\\SecurityDefense\\Middleware\\RequestThreatScanner::class,',
                $content
            );
            $filesystem->put($kernelPath, $content);
            $this->line('  → Injected WAF middleware into app/Http/Kernel.php');
        } else {
            $this->warn('  [WARN] No bootstrap/app.php or app/Http/Kernel.php found. Register RequestThreatScanner globally.');
        }
    }

    /**
     * Write the bridge subscriber class to app/Listeners/.
     */
    protected function createBridgeSubscriber(Filesystem $filesystem, bool $dryRun): void
    {
        $directory = app_path('Listeners');
        $target = $directory . '/AuthenticationSecuritySubscriber.php';

        if ($filesystem->exists($target) && ! (bool) $this->option('force')) {
            $this->line('  [OK] Bridge subscriber already exists (use --force to regenerate).');

            return;
        }

        if ($dryRun) {
            $this->line('  [DRY-RUN] Would write app/Listeners/AuthenticationSecuritySubscriber.php');

            return;
        }

        $filesystem->ensureDirectoryExists($directory);
        $filesystem->put($target, $this->buildSubscriberBody($this->authEventMapping()));
        $this->line('  → Created app/Listeners/AuthenticationSecuritySubscriber.php (' . count($this->authEventMapping()) . ' handlers)');
    }

    /**
     * Whether the bridge subscriber is already registered in the host app.
     */
    protected function isBridgeRegistered(): bool
    {
        $providerPath = app_path('Providers/AppServiceProvider.php');

        if (! is_file($providerPath)) {
            return false;
        }

        $content = (string) file_get_contents($providerPath);

        return str_contains($content, 'AuthenticationSecuritySubscriber')
            || str_contains($content, 'AuthenticationSecuritySubscriber::class');
    }
}