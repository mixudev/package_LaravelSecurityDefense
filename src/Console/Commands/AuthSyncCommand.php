<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Filesystem\Filesystem;

/**
 * Generates the event bridge between mixudev/security-defense and
 * mixudev/laravel-authentication: one subscriber file that forwards every
 * auth domain event (login failed/succeeded, lockout, 2FA, device, password,
 * session) into the SIEM/defense engine.
 *
 * Instalasi package auth (composer require, publish config, migrasi) sengaja
 * TIDAK ditangani di sini — itu urusan package auth itu sendiri
 * (php artisan authentication:install).
 */
class AuthSyncCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'auth:sync
                            {--force : Overwrite the existing bridge subscriber}
                            {--dry-run : Show the planned steps without writing anything}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Generate the security-defense event bridge subscriber for mixudev/laravel-authentication events';

    public function handle(Filesystem $filesystem): int
    {
        $dryRun = (bool) $this->option('dry-run');

        if (! $this->authPackageInstalled()) {
            if ($dryRun) {
                $this->line('  [DRY-RUN] mixudev/laravel-authentication not installed — would abort.');
            } else {
                $this->error('mixudev/laravel-authentication belum terpasang.');
            }

            $this->line('  Install dulu package auth-nya (urusan package itu sendiri):');
            $this->line('    composer require mixudev/laravel-authentication');
            $this->line('    php artisan authentication:install');
            $this->line('  Lalu jalankan ulang: php artisan auth:sync');

            return self::FAILURE;
        }

        $this->line('  [OK] mixudev/laravel-authentication detected.');

        // Generate the bridge subscriber (the only file auth:sync creates)
        $this->createBridgeSubscriber($filesystem, $dryRun);

        // Inject the package's own WAF middleware if not yet registered
        $this->injectWafMiddleware($filesystem, $dryRun);

        if ($dryRun) {
            $this->line('  [DRY-RUN] Would register ' . count($this->authEventMapping()) . ' auth event handlers.');

            return self::SUCCESS;
        }

        if (! $this->isBridgeRegistered()) {
            $this->line('  [NEXT] Register the subscriber in AppServiceProvider::boot():');
            $this->line('    Event::subscribe(\\App\\Listeners\\AuthenticationSecuritySubscriber::class);');
        } else {
            $this->line('  [OK] Bridge subscriber already registered.');
        }

        $this->newLine();
        $this->info('[DONE] auth:sync selesai. Bridge subscriber siap mendengarkan semua event package auth.');

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
        $useStatements = [];

        foreach ($events as $key => $mapping) {
            $eventClass = $mapping['event'];
            $shortClass = class_basename($eventClass);
            $handler = $this->subscriberMethodName($key);
            $method = $this->buildHandlerMethod($shortClass, $key, $mapping['eventType'], $mapping['fields']);
            if ($method !== null) {
                $methodBodies[] = $method;
                $handlers[] = "            {$shortClass}::class => '{$handler}',";
                $useStatements[] = "use {$eventClass};";
            }
        }

        sort($useStatements);
        $useImports = implode("\n", $useStatements);
        $subscribeMap = implode("\n", $handlers);
        $methods = implode("\n", $methodBodies);

        return <<<PHP
<?php

declare(strict_types=1);

namespace App\\Listeners;

use Illuminate\\Events\\Dispatcher;
use Mixudev\\SecurityDefense\\Support\\Facades\\SecurityDefense;
{$useImports}

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

    public function {$this->subscriberMethodName($key)}({$eventClass} \$event): void
    {
        SecurityDefense::record([
            'ip' => \$event->context->ipAddress,
            'identifier' => {$identifier},
            'eventType' => '{$eventType}',
            'userAgent' => \$event->context->userAgent,
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
     * Inject the package's own WAF middleware into the host application.
     * Laravel 11+ uses bootstrap/app.php; Laravel 10 uses app/Http/Kernel.php.
     * This is security-defense's own component, so auth:sync handles it.
     */
    protected function injectWafMiddleware(Filesystem $filesystem, bool $dryRun): void
    {
        $appBootstrap = $this->bootstrapFile();
        $kernelPath = $this->kernelFile();
        $needle = 'Mixudev\SecurityDefense\Middleware\RequestThreatScanner';

        if ($filesystem->exists($appBootstrap)) {
            $content = $filesystem->get($appBootstrap);

            if (str_contains($content, $needle)) {
                $this->line('  [OK] WAF middleware already registered in bootstrap/app.php');

                return;
            }

            if (str_contains($content, '$middleware->append(')) {
                if (! $dryRun) {
                    $content = str_replace(
                        '$middleware->append(',
                        '$middleware->append(\\Mixudev\\SecurityDefense\\Middleware\\RequestThreatScanner::class);' . PHP_EOL . '        $middleware->append(',
                        $content
                    );
                    $filesystem->put($appBootstrap, $content);
                    $this->line('  → Injected RequestThreatScanner into bootstrap/app.php');
                } else {
                    $this->line('  [DRY-RUN] Would inject RequestThreatScanner into bootstrap/app.php');
                }

                return;
            }

            $this->warn('  [WARN] bootstrap/app.php found but no $middleware->append( pattern. Register RequestThreatScanner manually.');
        } elseif ($filesystem->exists($kernelPath)) {
            $content = $filesystem->get($kernelPath);

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
            $this->line('  → Injected RequestThreatScanner into app/Http/Kernel.php');
        } else {
            $this->warn('  [WARN] No bootstrap/app.php or app/Http/Kernel.php found. Register RequestThreatScanner globally.');
        }
    }

    /**
     * Path to the Laravel 11+ bootstrap/app.php.
     */
    protected function bootstrapFile(): string
    {
        return base_path('bootstrap/app.php');
    }

    /**
     * Path to the Laravel 10 app/Http/Kernel.php.
     */
    protected function kernelFile(): string
    {
        return app_path('Http/Kernel.php');
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