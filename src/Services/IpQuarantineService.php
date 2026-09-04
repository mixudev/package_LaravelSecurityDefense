<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Services;

use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Support\Facades\Cache;

/**
 * Enterprise IP quarantine service (Fail2Ban-style active defense).
 * Temporarily isolates malicious IPs to stop attacks at the network boundary.
 */
class IpQuarantineService
{
    public function __construct(protected ?CacheRepository $cache = null)
    {
    }

    protected function getCache(): CacheRepository
    {
        if ($this->cache !== null) {
            return $this->cache;
        }

        $store = config('security-defense.cache_store');

        return Cache::store($store);
    }

    protected function getCacheKey(string $ip): string
    {
        $prefix = (string) config('security-defense.cache_prefix', 'security_defense:');

        return sprintf('%squarantine:%s', $prefix, md5($ip));
    }

    public function isEnabled(): bool
    {
        $global = (bool) config('security-defense.enabled', true);
        $quarantine = (bool) config('security-defense.middleware.quarantine.enabled', true);

        return $global && $quarantine;
    }

    /**
     * Check whether an IP is currently quarantined.
     */
    public function isQuarantined(string $ip): bool
    {
        if (!$this->isEnabled()) {
            return false;
        }

        if ($this->isWhitelisted($ip)) {
            return false;
        }

        return $this->getCache()->has($this->getCacheKey($ip));
    }

    /**
     * Put an IP into temporary quarantine jail.
     */
    public function jail(string $ip, ?int $duration = null, string $reason = 'Security policy violation'): bool
    {
        if ($this->isWhitelisted($ip)) {
            return false;
        }

        $quarantineDuration = $duration ?? (int) config('security-defense.middleware.quarantine.duration', 900);
        $cacheKey = $this->getCacheKey($ip);

        $this->getCache()->put($cacheKey, [
            'ip' => $ip,
            'jailed_at' => time(),
            'expires_at' => time() + $quarantineDuration,
            'reason' => $reason,
        ], $quarantineDuration);

        return true;
    }

    /**
     * Pardon / release an IP from quarantine.
     */
    public function pardon(string $ip): void
    {
        $this->getCache()->forget($this->getCacheKey($ip));
    }

    /**
     * Retrieve quarantine metadata for an IP.
     *
     * @return array{ip: string, jailed_at: int, expires_at: int, reason: string}|null
     */
    public function getDetails(string $ip): ?array
    {
        return $this->getCache()->get($this->getCacheKey($ip));
    }

    /**
     * Check if IP is in the whitelist.
     */
    public function isWhitelisted(string $ip): bool
    {
        $whitelist = (array) config('security-defense.middleware.quarantine.whitelist', ['127.0.0.1', '::1']);

        return in_array($ip, $whitelist, true);
    }
}
