<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Support;

use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Support\Facades\Cache;

/**
 * One-time, session-bound dashboard entry capability.
 *
 * Format URL (150 karakter, muat di route pattern {64,160}):
 *   encrypted . signature
 * encrypted = base64url(IV . AES-256-CBC(nonce|expires))  -> ~107 char
 * signature = base64url(HMAC-SHA256(encrypted))           -> ~43 char
 */
final class DashboardCapability
{
    /** Hanya cocok dengan token capability (150 char) / sessionPath (64 char). */
    public const ROUTE_PATTERN = '[A-Za-z0-9_-]{64,160}';

    private const CACHE_PREFIX = 'dashboard-capability:';

    public function __construct(private readonly ?CacheRepository $cache = null)
    {
    }

    public function issue(string $sessionId): string
    {
        $nonce = bin2hex(random_bytes(24));
        $expires = time() + $this->ttl();
        $plaintext = $nonce . '|' . $expires;

        $iv = random_bytes(16);
        $cipher = openssl_encrypt(
            $plaintext,
            'AES-256-CBC',
            $this->encryptionKey(),
            OPENSSL_RAW_DATA,
            $iv
        );
        if ($cipher === false) {
            throw new \RuntimeException('Failed to encrypt dashboard capability.');
        }

        $encrypted = $this->encode($iv . $cipher);
        $signature = $this->sign($encrypted);

        $this->cache()->put($this->key($nonce), hash('sha256', $sessionId), $this->ttl());

        return $encrypted . $signature;
    }

    /** Consume once and verify session binding. Returns session path or null. */
    public function consume(string $value, string $sessionId): ?string
    {
        $signatureLength = strlen($this->sign(''));
        if (strlen($value) <= $signatureLength) {
            return null;
        }

        $encrypted = substr($value, 0, -$signatureLength);
        $signature = substr($value, -$signatureLength);
        if ($encrypted === '' || ! hash_equals($this->sign($encrypted), $signature)) {
            return null;
        }

        try {
            $decoded = $this->decode($encrypted);
            if (strlen($decoded) < 17) { // IV (16) + minimal 1 byte cipher
                return null;
            }

            $iv = substr($decoded, 0, 16);
            $cipher = substr($decoded, 16);
            $plaintext = openssl_decrypt($cipher, 'AES-256-CBC', $this->encryptionKey(), OPENSSL_RAW_DATA, $iv);
        } catch (\Throwable) {
            return null;
        }

        if ($plaintext === false || ! str_contains($plaintext, '|')) {
            return null;
        }

        [$nonce, $expiresRaw] = explode('|', $plaintext, 2);
        $expires = (int) $expiresRaw;
        $sessionHash = hash('sha256', $sessionId);

        if (! ctype_xdigit($nonce) || strlen($nonce) !== 48 || $expires < time()) {
            return null;
        }

        $cache = $this->cache();
        $lock = method_exists($cache, 'lock') ? $cache->lock($this->key($nonce) . ':lock', 5) : null;
        $consume = function () use ($cache, $nonce, $sessionHash): bool {
            $stored = $cache->get($this->key($nonce));
            if (! is_string($stored) || ! hash_equals($stored, $sessionHash)) {
                return false;
            }
            $cache->forget($this->key($nonce));

            return true;
        };

        $ok = $lock !== null ? (bool) $lock->block(2, $consume) : $consume();

        if (!$ok) {
            return null;
        }

        // Session path is a per-entry random value (64 hex), NOT a
        // deterministic function of the session id. A URL leaked in an access
        // log no longer grants persistent access for the whole session life.
        return bin2hex(random_bytes(32));
    }

    public function sessionPath(string $sessionId): string
    {
        return substr(hash_hmac('sha256', 'session:' . hash('sha256', $sessionId), $this->hmacKey()), 0, 64);
    }

    public function isSessionPath(string $candidate, string $sessionId): bool
    {
        return hash_equals($this->sessionPath($sessionId), $candidate);
    }

    private function sign(string $value): string
    {
        return $this->encode(hash_hmac('sha256', 'security-defense:' . $value, $this->hmacKey(), true));
    }

    private function encryptionKey(): string
    {
        return hash_hkdf('sha256', $this->rawRootKey(), 32, 'security-defense:dashboard:encryption:v1');
    }

    private function hmacKey(): string
    {
        return hash_hkdf('sha256', $this->rawRootKey(), 32, 'security-defense:dashboard:hmac:v1');
    }

    private function rawRootKey(): string
    {
        // 1. Explicit isolated key takes precedence (zero blast radius on app.key).
        $custom = (string) config('security-defense.dashboard.key', env('SECURITY_DEFENSE_KEY', ''));
        if ($custom !== '') {
            return str_starts_with($custom, 'base64:') ? (string) base64_decode(substr($custom, 7), true) : $custom;
        }

        // 2. Fallback to app.key via HKDF derivation.
        $key = (string) config('app.key');

        return str_starts_with($key, 'base64:') ? (string) base64_decode(substr($key, 7), true) : $key;
    }

    private function encode(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }

    private function decode(string $value): string
    {
        return (string) base64_decode(strtr($value, '-_', '+/') . str_repeat('=', (4 - strlen($value) % 4) % 4), true);
    }

    private function key(string $nonce): string
    {
        return self::CACHE_PREFIX . hash('sha256', $nonce);
    }

    private function ttl(): int
    {
        return max(10, (int) config('security-defense.dashboard.opaque_path.ttl_seconds', 60));
    }

    private function cache(): CacheRepository
    {
        return $this->cache ?? Cache::store((string) config('security-defense.cache_store', Cache::getDefaultDriver()));
    }
}