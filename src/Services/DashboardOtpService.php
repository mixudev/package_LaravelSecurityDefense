<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Services;

use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Support\Facades\Cache;

/**
 * Lifecycle manager untuk Dashboard Authorization Code (OTP).
 *
 * Invariants:
 * - Kode 8 karakter, charset A-Z0-9, ~40 bit entropy dari random_bytes(5)
 * - Cache hanya menyimpan SHA-256 hash kode, bukan plaintext
 * - Consume-once: dihapus saat verifikasi berhasil
 * - Invalidasi penuh setelah max_attempts percobaan salah
 * - Terikat pada binding (session id + client IP) dari pemanggil
 * - Burst limiter per IP mencegah runaway code issuance
 *
 * ponytail: pending code + attempt counter tinggal di cache store yang dikonfigurasi.
 * Kalau operator menjalankan multi-instance dengan driver `file`, state tidak dibagi antar
 * node. Pakai Redis/Memcached saat horizontal scaling.
 */
final class DashboardOtpService
{
    public const CODE_LENGTH = 8;

    private const PREFIX = 'dashboard-otp:';
    private const ATTEMPT_PREFIX = 'dashboard-otp-attempts:';
    private const BURST_PREFIX = 'dashboard-otp-burst:';

    public function __construct(private readonly ?CacheRepository $cache = null)
    {
    }

    /**
     * Issue a new code, replacing any code previously issued for this binding.
     *
     * The plaintext is returned to the caller for delivery only. It is never
     * persisted and never logged.
     */
    public function generate(string $binding): string
    {
        $code = $this->makeCode();
        $cache = $this->cache();
        $key = $this->codeKey($binding);

        // Supersede any previous code and reset its attempt counter.
        $cache->forget($key);
        $cache->forget($this->attemptKey($binding));

        $cache->put($key, hash('sha256', $code), $this->ttl());

        return $code;
    }

    /**
     * Verify a submitted code against the pending code for this binding.
     *
     * A wrong guess increments an attempt counter; once max_attempts is reached
     * the code is destroyed so the attacker must make the operator re-issue.
     */
    public function verify(string $binding, string $input): bool
    {
        $cache = $this->cache();
        $codeKey = $this->codeKey($binding);
        $attemptKey = $this->attemptKey($binding);

        $stored = $cache->get($codeKey);
        if (! is_string($stored) || $stored === '') {
            return false;
        }

        if (! hash_equals($stored, hash('sha256', $this->normalize($input)))) {
            $this->registerFailure($cache, $codeKey, $attemptKey);

            return false;
        }

        // Consume atomically so two concurrent submits cannot both succeed.
        $lock = method_exists($cache, 'lock') ? $cache->lock($codeKey . ':lock', 5) : null;
        $consume = static function () use ($cache, $codeKey, $attemptKey): void {
            $cache->forget($codeKey);
            $cache->forget($attemptKey);
        };

        if ($lock !== null) {
            $lock->block(2, $consume);
        } else {
            $consume();
        }

        return true;
    }

    public function hasActivePendingCode(string $binding): bool
    {
        return $this->cache()->has($this->codeKey($binding));
    }

    /**
     * Read-only check; the caller increments only after a code was delivered.
     */
    public function canRequestCode(string $ip): bool
    {
        $max = max(1, (int) config('security-defense.dashboard.otp.max_codes_per_window', 3));
        $issued = (int) $this->cache()->get($this->burstKey($ip), 0);

        return $issued < $max;
    }

    public function incrementBurst(string $ip): void
    {
        $cache = $this->cache();
        $key = $this->burstKey($ip);
        $window = $this->window();

        $cache->add($key, 0, $window);
        $cache->increment($key);
    }

    /**
     * Drop any pending code and attempt counter for a binding.
     * Used when delivery fails so an undelivered code cannot be guessed.
     */
    public function discard(string $binding): void
    {
        $this->cache()->forget($this->codeKey($binding));
        $this->cache()->forget($this->attemptKey($binding));
    }

    private function registerFailure(CacheRepository $cache, string $codeKey, string $attemptKey): void
    {
        $max = max(1, (int) config('security-defense.dashboard.otp.max_attempts', 3));
        $attempts = (int) $cache->get($attemptKey, 0) + 1;

        if ($attempts >= $max) {
            $cache->forget($codeKey);
            $cache->forget($attemptKey);

            return;
        }

        $cache->put($attemptKey, $attempts, $this->ttl());
    }

    private function makeCode(): string
    {
        // 5 random bytes = 40 bits of entropy, rendered in base36 over
        // [0-9A-Z] and trimmed to exactly CODE_LENGTH characters.
        $encoded = strtoupper(base_convert(bin2hex(random_bytes(5)), 16, 36));

        return str_pad($encoded, self::CODE_LENGTH, '0', STR_PAD_LEFT);
    }

    private function normalize(string $input): string
    {
        return strtoupper(trim($input));
    }

    private function codeKey(string $binding): string
    {
        return self::PREFIX . hash('sha256', $binding);
    }

    private function attemptKey(string $binding): string
    {
        return self::ATTEMPT_PREFIX . hash('sha256', $binding);
    }

    private function burstKey(string $ip): string
    {
        return self::BURST_PREFIX . hash('sha256', $ip);
    }

    private function ttl(): int
    {
        return max(60, (int) config('security-defense.dashboard.otp.ttl_seconds', 300));
    }

    private function window(): int
    {
        return max(60, (int) config('security-defense.dashboard.otp.window_seconds', 900));
    }

    private function cache(): CacheRepository
    {
        return $this->cache ?? Cache::store(
            (string) config('security-defense.cache_store', Cache::getDefaultDriver())
        );
    }
}
