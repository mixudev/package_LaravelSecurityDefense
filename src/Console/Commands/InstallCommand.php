<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Console\Commands;

use Illuminate\Console\Command;
use Mixudev\SecurityDefense\Services\ConfigWriterService;
use RuntimeException;

/** Install package publishables and optional opaque dashboard capability. */
class InstallCommand extends Command
{
    protected $signature = 'security-defense:install
                            {--force : Overwrite published config}
                            {--with-opaque-path : Configure opaque dashboard path}
                            {--token= : Use supplied opaque path token}
                            {--no-migrate : Do not run database migrations}
                            {--no-cache : Do not clear or rebuild caches}
                            {--dry-run : Report actions without changing files or running commands}';

    protected $description = 'Install Security Defense package';

    public function handle(): int
    {
        $opaque = (bool) $this->option('with-opaque-path') || $this->option('token') !== null;
        $token = $this->option('token');

        if ($opaque) {
            if ($token !== null && ! $this->validToken((string) $token)) {
                $this->error('Opaque path token must contain 43-88 base64url characters.');
                return self::FAILURE;
            }
            $token ??= $this->environmentToken() ?? rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
            if (! $this->validToken($token)) {
                throw new RuntimeException('Generated opaque path token is invalid.');
            }
        }

        if ((bool) $this->option('dry-run')) {
            $this->info('Dry run: no files or commands changed.');
            return self::SUCCESS;
        }

        $this->call('vendor:publish', [
            '--tag' => 'security-defense-config',
            '--force' => (bool) $this->option('force'),
        ]);

        if ($opaque && $this->environmentToken() === null) {
            $this->writeEnvironmentToken($token);
        }

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
            // Resolver reads secret from env at route load; config:cache would freeze it.
            if (! $opaque) {
                $this->call('config:cache');
            }
        }

        $this->info('Security Defense installed.');
        return self::SUCCESS;
    }

    private function enableOpaquePath(): void
    {
        // Persist operator intent (feature switch, never the secret) via the
        // runtime overrides file. Secret itself lives only in host env.
        (new ConfigWriterService())->write([
            'dashboard.opaque_path.enabled' => true,
        ]);
    }

    private function validToken(string $token): bool
    {
        return preg_match('/^[A-Za-z0-9_-]{43,88}$/', $token) === 1;
    }

    private function environmentToken(): ?string
    {
        $value = getenv('SECURITY_DEFENSE_DASHBOARD_PATH');
        if ($value === false || trim($value) === '') {
            $value = $this->readEnvironmentToken();
        }

        return is_string($value) && $this->validToken(trim($value)) ? trim($value) : null;
    }

    private function readEnvironmentToken(): ?string
    {
        $path = base_path('.env');
        if (! is_file($path)) {
            return null;
        }

        $contents = file_get_contents($path);
        if ($contents === false || preg_match('/^SECURITY_DEFENSE_DASHBOARD_PATH=(.*)$/m', $contents, $match) !== 1) {
            return null;
        }

        return trim($match[1], " \t\"'");
    }

    private function writeEnvironmentToken(string $token): void
    {
        $path = base_path('.env');
        $contents = is_file($path) ? (string) file_get_contents($path) : '';
        $line = 'SECURITY_DEFENSE_DASHBOARD_PATH=' . $token;

        if (preg_match('/^SECURITY_DEFENSE_DASHBOARD_PATH=.*$/m', $contents) === 1) {
            $contents = preg_replace('/^SECURITY_DEFENSE_DASHBOARD_PATH=.*$/m', $line, $contents, 1);
        } else {
            $contents .= ($contents !== '' && ! str_ends_with($contents, "\n") ? "\n" : '') . $line . "\n";
        }

        $temporary = $path . '.' . bin2hex(random_bytes(8)) . '.tmp';
        if (file_put_contents($temporary, $contents, LOCK_EX) === false || ! rename($temporary, $path)) {
            @unlink($temporary);
            throw new RuntimeException('Unable to update .env atomically.');
        }
    }
}
