<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Filesystem\Filesystem;
use Mixudev\SecurityDefense\Services\ConfigWriterService;

/** Install package publishables and optional opaque dashboard capability. */
class InstallCommand extends Command
{
    protected $signature = 'security-defense:install
                            {--force : Overwrite published config}
                            {--with-opaque-path : Enable opaque (capability-gated) dashboard}
                            {--no-migrate : Do not run database migrations}
                            {--no-cache : Do not clear or rebuild caches}
                            {--dry-run : Report actions without changing files or running commands}
                            {--with-csp : Inject Content-Security-Policy middleware into bootstrap/app.php}';

    protected $description = 'Install Security Defense package';

    public function handle(Filesystem $filesystem): int
    {
        $opaque = (bool) $this->option('with-opaque-path');

        if ((bool) $this->option('dry-run')) {
            $this->info('Dry run: no files or commands changed.');

            return self::SUCCESS;
        }

        // Each step is verified: a failed publish, migration, or route cache
        // build leaves the package half-installed, so a silent SUCCESS here
        // tells the operator they are protected when they are not.
        if ($this->call('vendor:publish', [
            '--tag'   => 'security-defense-config',
            '--force' => (bool) $this->option('force'),
        ]) !== self::SUCCESS) {
            $this->error('Failed to publish the security-defense config file.');

            return self::FAILURE;
        }

        if ($opaque) {
            $this->enableOpaquePath();
        }

        // Auto-inject CSP middleware (opt-in via --with-csp flag or interactive prompt)
        if ($this->option('with-csp')) {
            $this->injectCspMiddleware($filesystem);
        } elseif ($this->input->isInteractive()) {
            if ($this->confirm('Would you like to add the Content-Security-Policy middleware to bootstrap/app.php?', true)) {
                $this->injectCspMiddleware($filesystem);
            }
        }

        if (! (bool) $this->option('no-migrate')) {
            if ($this->call('migrate', ['--force' => true]) !== self::SUCCESS) {
                $this->error('Database migrations failed. The security tables may be missing.');

                return self::FAILURE;
            }
        }

        if (! (bool) $this->option('no-cache')) {
            if ($this->call('route:clear') !== self::SUCCESS) {
                $this->error('Failed to clear the route cache.');

                return self::FAILURE;
            }

            if ($this->call('config:clear') !== self::SUCCESS) {
                $this->error('Failed to clear the configuration cache.');

                return self::FAILURE;
            }

            if ($this->call('route:cache') !== self::SUCCESS) {
                $this->error('Failed to build the route cache. Dashboard routes may not resolve.');

                return self::FAILURE;
            }
        }

        $this->info('Security Defense installed.');
        $this->newLine();
        $this->line('💡 <comment>CSP Middleware:</comment> To enable Content-Security-Policy headers,');
        $this->line('   re-run with: <info>php artisan security-defense:install --with-csp</info>');

        return self::SUCCESS;
    }

    /**
     * Inject the CSP middleware into the host application's bootstrap/app.php.
     *
     * Idempotent — skips if middleware already present.
     * Appends a web() middleware group registration inside ->withMiddleware().
     */
    protected function injectCspMiddleware(Filesystem $filesystem): void
    {
        $this->line('🔒 Configuring Content Security Policy middleware...');

        $bootstrapPath = base_path('bootstrap/app.php');

        if (! $filesystem->exists($bootstrapPath)) {
            $this->warn('  ⚠ bootstrap/app.php not found — skipping CSP injection.');

            return;
        }

        $content = $filesystem->get($bootstrapPath);

        // Skip if already injected
        if (str_contains($content, 'AddContentSecurityPolicy')) {
            $this->line('  <info>✓</info> CSP middleware already present in <comment>bootstrap/app.php</comment> — skipping.');

            return;
        }

        $injection = <<<'PHP'

        // Content Security Policy: Report-Only in local, Enforce in production.
        // Configure via config/security-defense.php or .env (SECURITY_CSP_*)
        $middleware->web(append: [
            \Mixudev\SecurityDefense\Http\Middleware\AddContentSecurityPolicy::class,
        ]);
PHP;

        // Find ->withMiddleware closure body and append the CSP block before closing brace
        $pattern = '/(->withMiddleware\(function\s*\(Middleware\s*\$middleware\)[^{]*\{)(.*?)(\s*\}\))/s';

        if (preg_match($pattern, $content, $matches)) {
            $replacement = $matches[1] . $matches[2] . $injection . "\n    " . ltrim($matches[3]);
            $newContent  = str_replace($matches[0], $replacement, $content);
            $filesystem->put($bootstrapPath, $newContent);
            $this->line('  <info>✓</info> CSP middleware injected into <comment>bootstrap/app.php</comment>.');
            $this->line('  <comment>→ Local: Report-Only (non-blocking). Production: Full enforcement.</comment>');
        } else {
            $this->warn('  ⚠ Could not auto-inject CSP middleware — pattern not matched.');
            $this->line('  Add manually to the web middleware group in <comment>bootstrap/app.php</comment>:');
            $this->line('    <info>\Mixudev\SecurityDefense\Http\Middleware\AddContentSecurityPolicy::class</info>');
        }
    }

    private function enableOpaquePath(): void
    {
        // Persist operator intent (feature switch, never a secret) via the
        // runtime overrides file. The capability itself is derived from
        // APP_KEY (Laravel Crypt + HMAC) at request time — no env token.
        (new ConfigWriterService())->write([
            'dashboard.opaque_path.enabled' => true,
        ]);
    }
}