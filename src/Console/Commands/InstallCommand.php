<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Filesystem\Filesystem;
use Mixudev\SecurityDefense\Services\ConfigWriterService;

/**
 * Enterprise automated installer for mixudev/security-defense.
 *
 * Installs all defensive components in one command without requiring any options:
 * - Publishes configuration
 * - Injects WAF (RequestThreatScanner) and CSP (AddContentSecurityPolicy) middlewares
 * - Enables capability-gated opaque dashboard
 * - Runs database migrations
 * - Optimizes and rebuilds route/config caches
 *
 * Options (--without-*, --no-*, --force) are strictly optional for granular customization.
 */
class InstallCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'security-defense:install
                            {--force : Overwrite published configuration and assets}
                            {--without-csp : Skip Content-Security-Policy middleware injection}
                            {--no-csp : Alias for --without-csp}
                            {--without-scanner : Skip RequestThreatScanner middleware injection}
                            {--no-scanner : Alias for --without-scanner}
                            {--without-opaque-path : Do not enable opaque capability-gated dashboard}
                            {--no-opaque-path : Alias for --without-opaque-path}
                            {--with-opaque-path : Explicitly enable opaque dashboard capability (enabled by default)}
                            {--without-migrations : Skip running database migrations}
                            {--no-migrate : Alias for --without-migrations}
                            {--without-cache : Skip clearing and rebuilding route/config caches}
                            {--no-cache : Alias for --without-cache}
                            {--dry-run : Report actions without changing files or executing commands}
                            {--with-csp : Explicitly enable CSP middleware injection (enabled by default)}';

    /**
     * The console command aliases.
     *
     * @var array<int, string>
     */
    protected $aliases = ['security:install'];

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Install and configure Security Defense enterprise protection';

    public function handle(Filesystem $filesystem): int
    {
        $this->info('🛡️  Installing mixudev/security-defense enterprise security engine...');
        $this->newLine();

        $force       = (bool) $this->option('force');
        $skipCsp     = (bool) $this->option('without-csp') || (bool) $this->option('no-csp');
        $skipScanner = (bool) $this->option('without-scanner') || (bool) $this->option('no-scanner');
        $skipOpaque  = (bool) $this->option('without-opaque-path') || (bool) $this->option('no-opaque-path');
        $skipMigrate = (bool) $this->option('without-migrations') || (bool) $this->option('no-migrate');
        $skipCache   = (bool) $this->option('without-cache') || (bool) $this->option('no-cache');

        if ((bool) $this->option('dry-run')) {
            $this->info('Dry run: no files or commands changed.');

            return self::SUCCESS;
        }

        // 1. Publish Configuration
        $this->line('📄 Publishing configuration...');
        if ($this->call('vendor:publish', [
            '--tag'   => 'security-defense-config',
            '--force' => $force,
        ]) !== self::SUCCESS) {
            $this->error('Failed to publish the security-defense config file.');

            return self::FAILURE;
        }
        $this->line('  <info>✓</info> Configuration published to <comment>config/security-defense.php</comment>');

        // 2. Enable Opaque Dashboard Capability (Default: ON for full defense, unless opted out)
        if (! $skipOpaque) {
            $this->enableOpaquePath();
            $this->line('  <info>✓</info> Opaque dashboard capability enabled (session & crypt-protected)');
        }

        // 3. Auto-configure Security Middlewares into bootstrap/app.php
        $this->configureMiddlewares($filesystem, skipScanner: $skipScanner, skipCsp: $skipCsp);

        // 4. Run Migrations
        if (! $skipMigrate) {
            $this->line('🗄️  Running database migrations...');
            if ($this->call('migrate', ['--force' => true]) !== self::SUCCESS) {
                $this->error('Database migrations failed. The security tables may be missing.');

                return self::FAILURE;
            }
            $this->line('  <info>✓</info> Database migrations executed successfully.');
        }

        // 5. Clear and Rebuild Caches
        if (! $skipCache) {
            $this->line('⚡ Optimizing routing and configuration caches...');
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
            $this->line('  <info>✓</info> Application caches rebuilt successfully.');
        }

        $this->newLine();
        $this->info('✨ mixudev/security-defense installed and operational!');
        $this->newLine();
        $this->line('🛡️  <comment>Active Defensive Layers:</comment>');
        $this->line('  • <info>WAF & Scanner</info>     : Real-time SQLi, XSS, Path Traversal, Bot & DDoS mitigation');
        $this->line('  • <info>CSP Protection</info>    : Automatic Report-Only in local, Strict Enforce in production');
        $this->line('  • <info>Opaque Dashboard</info>  : Capability-gated dashboard at <comment>/security-defense</comment>');
        $this->line('  • <info>Honeypots</info>         : Fake admin & actuator traps auto-blacklisting offenders');
        $this->newLine();
        $this->line('👉 <comment>Need fine-grained customization?</comment>');
        $this->line('   Run with options: <info>php artisan security-defense:install --no-csp --no-migrate --no-cache</info>');
        $this->newLine();

        return self::SUCCESS;
    }

    /**
     * Configure WAF and CSP middlewares in host application's bootstrap/app.php.
     *
     * Idempotent — will skip middlewares that are already present.
     */
    protected function configureMiddlewares(Filesystem $filesystem, bool $skipScanner = false, bool $skipCsp = false): void
    {
        $bootstrapPath = base_path('bootstrap/app.php');

        if (! $filesystem->exists($bootstrapPath)) {
            return;
        }

        $content = $filesystem->get($bootstrapPath);

        $hasScanner = str_contains($content, 'RequestThreatScanner');
        $hasCsp     = str_contains($content, 'AddContentSecurityPolicy');

        $injections = '';

        if (! $skipScanner && ! $hasScanner) {
            $injections .= <<<'PHP'

        // Enterprise WAF & Threat Scanner
        $middleware->append(\Mixudev\SecurityDefense\Middleware\RequestThreatScanner::class);
PHP;
        }

        if (! $skipCsp && ! $hasCsp) {
            $injections .= <<<'PHP'

        // Content Security Policy: Report-Only in local, Enforce in production
        $middleware->web(append: [
            \Mixudev\SecurityDefense\Http\Middleware\AddContentSecurityPolicy::class,
        ]);
PHP;
        }

        if ($injections !== '') {
            $pattern = '/(->withMiddleware\s*\(\s*function\s*\(\s*Middleware\s*\$middleware\s*\)[^{]*\{)(.*?)(\s*\}\))/s';

            if (preg_match($pattern, $content, $matches)) {
                $replacement = $matches[1] . $matches[2] . $injections . "\n    " . ltrim($matches[3]);
                $newContent  = str_replace($matches[0], $replacement, $content);
                $filesystem->put($bootstrapPath, $newContent);
                $this->line('  <info>✓</info> Security middlewares registered in <comment>bootstrap/app.php</comment>');
            } else {
                $this->warn('  ⚠ Could not auto-inject middlewares into bootstrap/app.php — please register them manually.');
            }
        } else {
            $this->line('  <info>✓</info> Security middlewares already registered in <comment>bootstrap/app.php</comment>');
        }
    }

    private function enableOpaquePath(): void
    {
        // Persist operator intent via the runtime overrides file.
        // The capability itself is derived from APP_KEY at request time.
        (new ConfigWriterService())->write([
            'dashboard.opaque_path.enabled' => true,
        ]);
    }
}