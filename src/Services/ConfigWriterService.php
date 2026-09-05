<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Services;

use Illuminate\Support\Facades\Artisan;
use Throwable;

/**
 * Runtime configuration writer for security-defense dashboard toggles.
 *
 * Persists quick-action changes into a dedicated overrides file
 * (config/security-defense-overrides.php) that the service provider merges on
 * top of the published config. This keeps the published config file pristine,
 * supports arbitrarily nested dot-notation keys via Laravel's config merge,
 * and survives cache flushes by clearing the config cache after each write.
 */
class ConfigWriterService
{
    public function __construct(protected ?string $overridesPath = null)
    {
        $this->overridesPath ??= config_path('security-defense-overrides.php');
    }

    /**
     * Retrieve the currently persisted overrides (empty when none yet).
     *
     * @return array<string, mixed> dot-notation key => value pairs
     */
    public function read(): array
    {
        if (!is_file($this->overridesPath)) {
            return [];
        }

        $loaded = @require $this->overridesPath;

        return is_array($loaded) ? $loaded : [];
    }

    /**
     * Persist nested key => value pairs into the overrides file and apply them
     * to the runtime config immediately.
     *
     * @param  array<string, mixed>  $values  dot-notation key => value pairs
     */
    public function write(array $values): bool
    {
        $current = $this->read();
        foreach ($values as $key => $value) {
            $current[$key] = $value;
        }

        $persisted = false;

        if (is_writable(config_path()) || !is_file($this->overridesPath)) {
            $persisted = $this->writeFile($this->overridesPath, $current);
        }

        foreach ($values as $key => $value) {
            config(["security-defense.{$key}" => $value]);
        }

        if ($persisted && $this->configurationIsCached()) {
            try {
                Artisan::call('config:clear');
            } catch (Throwable) {
                // Non-fatal: next deploy refreshes the cache.
            }
        }

        return $persisted;
    }

    protected function configurationIsCached(): bool
    {
        $app = app();

        return method_exists($app, 'configurationIsCached') && $app->configurationIsCached();
    }

    /**
     * Serialize the overrides as a PHP config array file.
     *
     * @param  array<string, mixed>  $overrides
     */
    protected function writeFile(string $path, array $overrides): bool
    {
        $lines = ["<?php", '', 'return [', ''];
        foreach ($overrides as $key => $value) {
            $lines[] = sprintf("    '%s' => %s,", $key, var_export($value, true));
        }
        $lines[] = '];';
        $lines[] = '';

        return @file_put_contents($path, implode("\n", $lines), LOCK_EX) !== false;
    }
}