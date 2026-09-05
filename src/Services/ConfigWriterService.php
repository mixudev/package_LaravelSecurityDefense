<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Services;

use Illuminate\Support\Facades\Artisan;
use Throwable;

/**
 * Runtime configuration writer for security-defense dashboard toggles.
 *
 * Persists quick-action changes directly into the published
 * config/security-defense.php file so they survive cache flushes and restarts.
 * Supports scalar leaves (e.g. 'block_headless_clients') and flat-array leaves
 * (e.g. 'middleware.quarantine.whitelist').
 *
 * ponytail: only scalar + flat-array keys are supported; nested-array values
 * beyond one level are not rewritten (falls back to runtime override). Extend
 * the literal formatter when a nested quick-action toggle is needed.
 */
class ConfigWriterService
{
    public function __construct(protected ?string $configPath = null)
    {
        $this->configPath ??= config_path('security-defense.php');
    }

    /**
     * Persist nested key => value pairs into the published config file.
     * Always applies the runtime override so behaviour changes immediately,
     * even when the file is not writable.
     *
     * @param  array<string, mixed>  $values  dot-notation key => value pairs
     */
    public function write(array $values): bool
    {
        $persisted = false;

        if (is_file($this->configPath) && is_writable($this->configPath)) {
            $persisted = $this->writeToFile($this->configPath, $values);
        }

        foreach ($values as $key => $value) {
            config(["security-defense.{$key}" => $value]);
        }

        // A cached config would ignore the on-disk edit until cleared.
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

    protected function writeToFile(string $path, array $values): bool
    {
        $contents = file_get_contents($path);
        if ($contents === false) {
            return false;
        }

        $updated = $contents;
        foreach ($values as $key => $value) {
            $leaf = $this->leaf($key);

            if (is_array($value)) {
                $replacement = $this->arrayLiteral($value);
                $pattern = sprintf("/('%s'\s*=>\s*)\[[^\]]*\]/s", preg_quote($leaf, '/'));
            } else {
                $replacement = var_export($value, true);
                $pattern = sprintf("/('%s'\s*=>\s*)[^,\n]+/", preg_quote($leaf, '/'));
            }

            if (preg_match($pattern, $updated) !== 1) {
                return false;
            }
            $updated = preg_replace($pattern, '$1' . str_replace('$', '\\$', $replacement), $updated, 1);
        }

        return @file_put_contents($path, $updated, LOCK_EX) !== false;
    }

    protected function leaf(string $key): string
    {
        $segments = explode('.', $key);

        return (string) end($segments);
    }

    /**
     * Render a flat array as a PHP literal preserving config-file style.
     *
     * @param  array<int|string, mixed>  $value
     */
    protected function arrayLiteral(array $value): string
    {
        $items = [];
        foreach ($value as $item) {
            $items[] = '            ' . var_export($item, true) . ',';
        }

        return "[\n" . implode("\n", $items) . "\n        ]";
    }
}