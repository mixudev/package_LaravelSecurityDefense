<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Services;

use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Support\Facades\Cache;
use Mixudev\SecurityDefense\DTO\SecurityThreat;

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
 * Semua counter (attempts, burst) memakai operasi atomik `add()` + `increment()`.
 * Pola `get()` lalu `put()` adalah read-modify-write dan bisa dikalahkan request paralel:
 * semua penebak paralel membaca nilai yang sama lalu menulis nilai yang sama, sehingga
 * batas percobaan tidak pernah tercapai.
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

    /** @var callable(SecurityThreat): void|null */
    private $bruteForceReporter = null;

    public function __construct(private readonly ?CacheRepository $cache = null)
    {
    }

    /**
     * Register a sink for brute-force alerts (wired to AlertDispatcher by the
     * service provider). Kept as a callback so this service never hard-depends
     * on the alert pipeline.
     *
     * @param callable(SecurityThreat): void $reporter
     */
    public function onBruteForce(callable $reporter): void
    {
        $this->bruteForceReporter = $reporter;
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
     * A wrong guess increments an attempt counter atomically; once max_attempts is
     * reached the code is destroyed so the attacker must make the operator re-issue,
     * and a brute-force threat is raised.
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
            $attempts = $this->registerFailure($cache, $codeKey, $attemptKey);

            // Raised outside the lock: the alert pipeline does I/O and must not
            // hold the binding lock.
            if ($attempts !== null) {
                $this->reportBruteForce($binding, $attempts);
            }

            return false;
        }

        $consume = static function () use ($cache, $codeKey, $attemptKey): void {
            $cache->forget($codeKey);
            $cache->forget($attemptKey);
        };

        \Mixudev\SecurityDefense\Support\CacheLock::run($cache, $codeKey . ':lock', 5, $consume);

        return true;
    }

    public function hasActivePendingCode(string $binding): bool
    {
        return $this->cache()->has($this->codeKey($binding));
    }

    /**
     * Atomically reserve one code-issuance slot for an IP.
     *
     * The check and the increment MUST be a single operation: a separate
     * canRequestCode() + incrementBurst() pair lets N concurrent requests all
     * observe a clean counter and all proceed, overshooting the burst ceiling
     * by N. Returns false once the window quota is exhausted.
     */
    public function acquireRequestSlot(string $ip): bool
    {
        $max = max(1, (int) config('security-defense.dashboard.otp.max_codes_per_window', 3));

        return \Mixudev\SecurityDefense\Support\CacheLock::reserveSlot(
            $this->cache(),
            $this->burstKey($ip),
            $max,
            $this->window()
        );
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

    /**
     * Record one failed guess atomically.
     *
     * @return int|null Total attempts when the ceiling was reached (code
     *                  destroyed), null while guesses remain under the limit.
     */
    private function registerFailure(CacheRepository $cache, string $codeKey, string $attemptKey): ?int
    {
        $max = max(1, (int) config('security-defense.dashboard.otp.max_attempts', 3));

        $record = function () use ($cache, $codeKey, $attemptKey, $max): ?int {
            $cache->add($attemptKey, 0, $this->ttl());
            $attempts = (int) $cache->increment($attemptKey);

            if ($attempts >= $max) {
                $cache->forget($codeKey);
                $cache->forget($attemptKey);

                return $attempts;
            }

            return null;
        };

        return \Mixudev\SecurityDefense\Support\CacheLock::run($cache, $attemptKey . ':lock', 5, $record);
    }

    private function reportBruteForce(string $binding, int $attempts): void
    {
        if ($this->bruteForceReporter === null) {
            return;
        }

        if (! (bool) config('security-defense.dashboard.otp.alert_on_brute_force', true)) {
            return;
        }

        [$sessionId, $ip] = array_pad(explode('_', $binding, 2), 2, '');

        try {
            ($this->bruteForceReporter)(new SecurityThreat(
                severity: (string) config('security-defense.dashboard.otp.brute_force_severity', 'high'),
                threatType: 'dashboard_otp_brute_force',
                // Bound to the IP only: a re-issued code on the same address
                // must not be able to suppress the alert by changing session.
                fingerprint: hash('sha256', 'dashboard_otp_brute_force:' . $ip),
                metadata: [
                    'ip' => $ip,
                    'attempts' => $attempts,
                    'session_ref' => substr(hash('sha256', $sessionId), 0, 16),
                ],
                ruleIdentifier: 'dashboard_otp'
            ));
        } catch (\Throwable $e) {
            // Alerting must never turn a rejected login into a 500.
            logger()->warning('[SecurityDefense] Failed to report dashboard OTP brute force.', [
                'error' => $e->getMessage(),
            ]);
        }
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
