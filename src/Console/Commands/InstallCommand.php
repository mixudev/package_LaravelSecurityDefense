<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Console\Commands;

use Illuminate\Console\Command;
use Mixudev\SecurityDefense\Services\ConfigWriterService;

/** Install package publishables and optional opaque dashboard capability. */
class InstallCommand extends Command
{
    protected $signature = 'security-defense:install
                            {--force : Overwrite published config}
                            {--with-opaque-path : Enable opaque (capability-gated) dashboard}
                            {--no-migrate : Do not run database migrations}
                            {--no-cache : Do not clear or rebuild caches}
                            {--dry-run : Report actions without changing files or running commands}';

    protected $description = 'Install Security Defense package';

    public function handle(): int
    {
        $opaque = (bool) $this->option('with-opaque-path');

        if ((bool) $this->option('dry-run')) {
            $this->info('Dry run: no files or commands changed.');
            return self::SUCCESS;
        }

        $this->call('vendor:publish', [
            '--tag' => 'security-defense-config',
            '--force' => (bool) $this->option('force'),
        ]);

        if ($opaque) {
            $this->enableOpaquePath();
        }

        if (! (bool) $this->option('no-migrate')) {
            $this->call('migrate', ['--force' => true]);
        }

        if (! (bool) $this->option('no-cache')) {
            $this->call('route:clear');
            $this->call('config:clear');
            $this->call('route:cache');
        }

        $this->info('Security Defense installed.');
        return self::SUCCESS;
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