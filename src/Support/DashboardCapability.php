<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Support;

use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Encryption\Encrypter;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Str;

/** One-time, session-bound dashboard entry capability. */
final class DashboardCapability
{
    public const ROUTE_PATTERN = '[A-Za-z0-9_-]++';

    private const CACHE_PREFIX = 'dashboard-capability:';

    public function __construct(private readonly ?CacheRepository $cache = null)
    {
    }

    public function issue(string $sessionId): string
    {
        $nonce = Str::random(64);
        $now = time();
        $payload = json_encode([
            'purpose' => 'security-defense.dashboard.entry',
            'nonce' => $nonce,
            'session' => hash('sha256', $sessionId),
            'issued_at' => $now,
            'expires_at' => $now + $this->ttl(),
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);

        $encrypter = $this->encrypter();
        $encrypted = $this->encode($encrypter->encryptString($payload));
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
        if ($encrypted === '' || !hash_equals($this->sign($encrypted), $signature)) {
            return null;
        }

        try {
            $encrypter = $this->encrypter();
            $payload = json_decode($encrypter->decryptString($this->decode($encrypted)), true, 8, JSON_THROW_ON_ERROR);
        } catch (\Throwable) {
            return null;
        }

        $nonce = is_string($payload['nonce'] ?? null) ? $payload['nonce'] : '';
        $expires = (int) ($payload['expires_at'] ?? 0);
        $sessionHash = hash('sha256', $sessionId);
        if ($nonce === '' || $expires < time() || !hash_equals((string) ($payload['session'] ?? ''), $sessionHash)) {
            return null;
        }

        $cache = $this->cache();
        $lock = method_exists($cache, 'lock') ? $cache->lock($this->key($nonce) . ':lock', 5) : null;
        $consume = function () use ($cache, $nonce, $sessionHash): bool {
            $stored = $cache->get($this->key($nonce));
            if (!is_string($stored) || !hash_equals($stored, $sessionHash)) {
                return false;
            }
            $cache->forget($this->key($nonce));
            return true;
        };

        $ok = $lock !== null ? (bool) $lock->block(2, $consume) : $consume();

        return $ok ? $this->sessionPath($sessionId) : null;
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

    private function encrypter(): Encrypter
    {
        return new Encrypter($this->encryptionKey(), 'AES-256-CBC');
    }

    private function encryptionKey(): string
    {
        $raw = $this->rawRootKey();

        return hash_hkdf('sha256', $raw, 32, 'security-defense:dashboard:encryption:v1');
    }

    private function hmacKey(): string
    {
        $raw = $this->rawRootKey();

        return hash_hkdf('sha256', $raw, 32, 'security-defense:dashboard:hmac:v1');
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
