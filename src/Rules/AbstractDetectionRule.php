<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Rules;

use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Support\Facades\Cache;
use Mixudev\SecurityDefense\Contracts\DetectionRule;

/**
 * Base abstract class providing config and cache helpers for detection rules.
 */
abstract class AbstractDetectionRule implements DetectionRule
{
    /**
     * @param CacheRepository|null $cache
     */
    public function __construct(protected ?CacheRepository $cache = null)
    {
    }

    /**
     * Retrieve the cache repository configured for the package.
     */
    protected function getCache(): CacheRepository
    {
        if ($this->cache !== null) {
            return $this->cache;
        }

        $store = config('security-defense.cache_store');

        return Cache::store($store);
    }

    /**
     * Build a cache key scoped with package prefix.
     */
    protected function getCacheKey(string $key): string
    {
        $prefix = (string) config('security-defense.cache_prefix', 'security_defense:');

        return sprintf('%srule:%s:%s', $prefix, $this->identifier(), $key);
    }

    /**
     * Retrieve configuration value for this rule.
     */
    protected function getConfig(string $key, mixed $default = null): mixed
    {
        return config(sprintf('security-defense.detection.rules.%s.%s', $this->identifier(), $key), $default);
    }

    /**
     * Determine if this rule is enabled in configuration.
     */
    public function isEnabled(): bool
    {
        $globalEnabled = (bool) config('security-defense.enabled', true);
        $detectionEnabled = (bool) config('security-defense.detection.enabled', true);
        $ruleEnabled = (bool) $this->getConfig('enabled', true);

        return $globalEnabled && $detectionEnabled && $ruleEnabled;
    }
}
