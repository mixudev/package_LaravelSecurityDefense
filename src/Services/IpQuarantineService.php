<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Services;

use Closure;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Support\Facades\Cache;
use Mixudev\SecurityDefense\Models\SecurityQuarantine;

/**
 * Enterprise IP quarantine service (Fail2Ban-style active defense).
 * Temporarily isolates malicious IPs to stop attacks at the network boundary.
 * Supports optional durable DB-backed quarantine for multi-server / cache-flush resilience.
 */
class IpQuarantineService
{
    /** Maximum quarantine duration in seconds (24 hours). */
    private const MAX_DURATION = 86400;

    /** Maximum reason string length (DB column safe). */
    private const MAX_REASON_LENGTH = 255;

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

    /**
     * Whether durable DB-backed quarantine persistence is enabled.
     */
    protected function persistToDatabase(): bool
    {
        return (bool) config('security-defense.middleware.quarantine.persist_to_database', false);
    }

    /**
     * When true, DB failure during isQuarantined() treats unknown state as quarantined (fail-closed).
     * When false (default), unknown state returns false to avoid blocking clean traffic on DB outage.
     */
    protected function dbFailClosed(): bool
    {
        return (bool) config('security-defense.middleware.quarantine.db_fail_closed', false);
    }

    public function isEnabled(): bool
    {
        $global = (bool) config('security-defense.enabled', true);
        $quarantine = (bool) config('security-defense.middleware.quarantine.enabled', true);

        return $global && $quarantine;
    }

    /**
     * Validate IP address format using inet_pton (stdlib, no filter_var dependency).
     */
    protected function isValidIp(string $ip): bool
    {
        return inet_pton($ip) !== false;
    }

    /**
     * Clamp duration to [1, MAX_DURATION].
     * Rejects zero/negative → 1, huge values → MAX_DURATION.
     */
    protected function clampDuration(?int $duration): int
    {
        $default = (int) config('security-defense.middleware.quarantine.duration', 900);

        if ($duration === null) {
            return max(1, min($default, self::MAX_DURATION));
        }

        return max(1, min($duration, self::MAX_DURATION));
    }

    /**
     * Bound reason string length to prevent DB column overflow.
     */
    protected function boundReason(string $reason): string
    {
        return mb_substr($reason, 0, self::MAX_REASON_LENGTH, 'UTF-8');
    }

    /**
     * Check whether an IP is currently quarantined.
     */
    public function isQuarantined(string $ip): bool
    {
        if (!$this->isValidIp($ip)) {
            return false;
        }

        if (!$this->isEnabled()) {
            return false;
        }

        if ($this->isWhitelisted($ip)) {
            return false;
        }

        // Fast path: cache
        if ($this->getCache()->has($this->getCacheKey($ip))) {
            return true;
        }

        // Durable path: DB-backed quarantine survives cache flush / restart
        if ($this->persistToDatabase()) {
            try {
                return SecurityQuarantine::query()
                    ->forIp($ip)
                    ->active()
                    ->exists();
            } catch (\Throwable) {
                // SEC-004/SEC-012: DB unavailable after cache miss — indeterminate state.
                // db_fail_closed=true → treat unknown as quarantined (safe for active threat indicators).
                // db_fail_closed=false → allow traffic (fail-open) to avoid blocking every clean request.
                return $this->dbFailClosed();
            }
        }

        return false;
    }

    /**
     * Put an IP into temporary quarantine jail.
     */
    public function jail(string $ip, ?int $duration = null, string $reason = 'Security policy violation'): bool
    {
        return $this->withIpLock($ip, fn (): bool => $this->jailUnlocked($ip, $duration, $reason));
    }

    private function jailUnlocked(string $ip, ?int $duration, string $reason): bool
    {
        if (!$this->isValidIp($ip)) {
            return false;
        }

        if ($this->isWhitelisted($ip)) {
            return false;
        }

        $quarantineDuration = $this->clampDuration($duration);
        $reason = $this->boundReason($reason);
        $cacheKey = $this->getCacheKey($ip);
        $expiresAt = time() + $quarantineDuration;

        $this->getCache()->put($cacheKey, [
            'ip' => $ip,
            'jailed_at' => time(),
            'expires_at' => $expiresAt,
            'reason' => $reason,
        ], $quarantineDuration);

        // Durable path: upsert DB record when enabled
        if ($this->persistToDatabase()) {
            try {
                SecurityQuarantine::query()
                    ->updateOrCreate(
                        ['ip' => $ip],
                        [
                            'jailed_at' => now(),
                            'expires_at' => now()->addSeconds($quarantineDuration),
                            'reason' => $reason,
                        ]
                    );
            } catch (\Throwable) {
                // Cache jail is already active; DB fail does not prevent mitigation
            }
        }

        // Fire official event for host application listeners
        event(new \Mixudev\SecurityDefense\Events\IpQuarantined($ip, $quarantineDuration, $reason));

        return true;
    }

    /**
     * Pardon / release an IP from quarantine.
     */
    public function pardon(string $ip): void
    {
        $this->withIpLock($ip, function () use ($ip): void {
            if (!$this->isValidIp($ip)) {
                return;
            }

            $this->getCache()->forget($this->getCacheKey($ip));
            if ($this->persistToDatabase()) {
                try {
                    SecurityQuarantine::query()->forIp($ip)->delete();
                } catch (\Throwable) {
                    // Ignore; cache already cleared
                }
            }
        });
    }

    /**
     * Serialize jail/pardon mutations per IP when cache store supports locks.
     */
    private function withIpLock(string $ip, Closure $operation): mixed
    {
        $cache = $this->getCache();
        if (!method_exists($cache, 'lock')) {
            return $operation();
        }

        return $cache->lock($this->getCacheKey($ip) . ':mutation', 10)->block(3, $operation);
    }

    /**
     * Retrieve quarantine metadata for an IP.
     *
     * @return array{ip: string, jailed_at: int, expires_at: int, reason: string}|null
     */
    public function getDetails(string $ip): ?array
    {
        if (!$this->isValidIp($ip)) {
            return null;
        }

        // Check cache first
        $cached = $this->getCache()->get($this->getCacheKey($ip));
        if (is_array($cached)) {
            return $cached;
        }

        // Fallback to DB-backed record
        if ($this->persistToDatabase()) {
            try {
                $record = SecurityQuarantine::query()->forIp($ip)->active()->first();
                if ($record !== null) {
                    return [
                        'ip' => $record->ip,
                        'jailed_at' => $record->jailed_at?->getTimestamp() ?? time(),
                        'expires_at' => $record->expires_at->getTimestamp(),
                        'reason' => $record->reason ?? '',
                    ];
                }
            } catch (\Throwable) {
                // return null below
            }
        }

        return null;
    }

    /**
     * Check if IP is in the whitelist.
     */
    public function isWhitelisted(string $ip): bool
    {
        $whitelist = $this->whitelist();

        return in_array($ip, $whitelist, true);
    }

    /**
     * Retrieve the current whitelist entries.
     *
     * @return array<int, string>
     */
    public function whitelist(): array
    {
        return array_values(array_unique(array_map('strval', (array) config('security-defense.middleware.quarantine.whitelist', ['127.0.0.1', '::1']))));
    }

    /**
     * Permanently whitelist an IP (survives restarts) and pardon it immediately.
     * Persists into the published config file when writable, otherwise runtime-only.
     */
    public function whitelistIp(string $ip): bool
    {
        if ($this->isWhitelisted($ip)) {
            return true;
        }

        $whitelist = $this->whitelist();
        $whitelist[] = $ip;
        $whitelist = array_values(array_unique($whitelist));

        $persisted = app(ConfigWriterService::class)->write([
            'middleware.quarantine.whitelist' => $whitelist,
        ]);

        // Always release the IP from quarantine so the exemption applies instantly.
        $this->pardon($ip);

        return $persisted;
    }
}
