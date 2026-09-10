<?php
declare(strict_types=1);

namespace Mixudev\SecurityDefense\Epistemic\Memory;

use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Mixudev\SecurityDefense\Epistemic\Contracts\ExperienceMemoryInterface;
use Throwable;

final class ExperienceMemory implements ExperienceMemoryInterface
{
    private string $prefix;
    private string $indexKey;
    private int $maxPatterns;
    private int $retentionSeconds;

    public function __construct(private readonly CacheRepository $cache, string $cachePrefix = 'security_defense:', int $maxPatterns = 10000, int $retentionDays = 30)
    {
        $this->prefix = $cachePrefix . 'ep:pattern:';
        $this->indexKey = $cachePrefix . 'ep:pattern-index';
        $this->maxPatterns = max(0, $maxPatterns);
        $this->retentionSeconds = max(1, $retentionDays * 86400);
    }

    public function recall(string $patternKey): ?ThreatPattern
    {
        if (!$this->validPatternKey($patternKey)) return null;
        $key = $this->cacheKey($patternKey);
        $data = $this->cache->get($key);
        if (!is_array($data)) return null;

        $now = time();
        $expiresAt = isset($data['expires_at']) ? (int) $data['expires_at'] : $this->legacyExpiry($data, $now);
        if ($expiresAt <= $now) return null;
        if (!isset($data['expires_at'])) {
            $data['expires_at'] = $expiresAt;
            $this->cache->put($key, $data, $expiresAt - $now);
        }

        return new ThreatPattern(key: $data['key'], confidence: (float) $data['confidence'], truePositiveCount: (int) ($data['tp'] ?? 0), falsePositiveCount: (int) ($data['fp'] ?? 0), lastOutcome: $data['last_outcome'] ?? null, lastSeenAt: $data['last_seen_at'] ?? null);
    }

    public function store(ThreatPattern $pattern): void
    {
        if (!$this->validPatternKey($pattern->key) || $this->maxPatterns === 0) return;
        $this->withLock(fn () => $this->storeUnlocked($pattern));
    }

    private function storeUnlocked(ThreatPattern $pattern): void
    {
        {
            $key = $this->cacheKey($pattern->key);
            $now = time();
            $old = $this->cache->get($key);
            $expiresAt = is_array($old) && isset($old['expires_at']) ? (int) $old['expires_at'] : $now + $this->retentionSeconds;
            $remaining = $expiresAt - $now;
            if ($remaining < 1) return;
            $index = $this->patternIndex();
            $hash = $this->patternHash($pattern->key);
            if (!isset($index[$hash]) && count($index) >= $this->maxPatterns) return;
            $index[$hash] = (int) ($index[$hash] ?? $expiresAt);
            $this->cache->put($this->indexKey, $index, max(1, min($this->retentionSeconds, max($index) - $now)));
            $this->cache->put($key, ['key' => $pattern->key, 'confidence' => $pattern->confidence, 'tp' => $pattern->truePositiveCount, 'fp' => $pattern->falsePositiveCount, 'last_outcome' => $pattern->lastOutcome, 'last_seen_at' => $pattern->lastSeenAt, 'expires_at' => $expiresAt], $remaining);
        }
    }

    public function recordFeedback(string $patternKey, string $outcome, ?string $feedbackId = null): void
    {
        if (!in_array($outcome, ['confirmed_attack', 'false_positive'], true) || !$this->validPatternKey($patternKey)) return;
        $this->withLock(function () use ($patternKey, $outcome, $feedbackId): void {
            if ($feedbackId !== null && (!$this->validFeedbackId($feedbackId) || !$this->cache->add($this->processedKey($feedbackId), true, $this->retentionSeconds))) return;
            $pattern = $this->recall($patternKey) ?? new ThreatPattern($patternKey, 0.5);
            $outcome === 'confirmed_attack' ? $pattern->recordTruePositive() : $pattern->recordFalsePositive();
            $this->storeUnlocked($pattern);
        }, function () use ($patternKey, $outcome, $feedbackId): void {
            if ($feedbackId !== null && (!$this->validFeedbackId($feedbackId) || !$this->cache->add($this->processedKey($feedbackId), true, $this->retentionSeconds))) return;
            $pattern = $this->recall($patternKey) ?? new ThreatPattern($patternKey, 0.5);
            $counter = $this->counterKey($patternKey, $outcome);
            $this->cache->add($counter, 0, $this->retentionSeconds);
            $this->cache->increment($counter);
            $count = (int) $this->cache->get($counter, 0);
            if ($outcome === 'confirmed_attack') {
                $pattern->truePositiveCount = max($pattern->truePositiveCount, $count);
                $pattern->confidence = min(1.0, $pattern->confidence + 0.02);
                $pattern->lastOutcome = 'confirmed_attack';
            } else {
                $pattern->falsePositiveCount = max($pattern->falsePositiveCount, $count);
                $pattern->confidence = max(0.0, $pattern->confidence - 0.05);
                $pattern->lastOutcome = 'false_positive';
            }
            $pattern->lastSeenAt = gmdate(DATE_ATOM);
            $this->storeUnlocked($pattern);
        });
    }

    private function withLock(callable $callback, ?callable $fallback = null): void
    {
        if (isset($this->noLock)) { ($fallback ?? $callback)(); return; }
        try {
            if (method_exists($this->cache, 'lock')) {
                $lock = $this->cache->lock($this->prefix . 'lock', 10);
                $lock->block(5, $callback);
                return;
            }
        } catch (Throwable) {
            // Cache driver has no usable lock; use atomic counters below.
        }
        ($fallback ?? $callback)();
    }

    private function legacyExpiry(array $data, int $now): int
    {
        $seenAt = $data['last_seen_at'] ?? null;
        $seenTimestamp = is_string($seenAt) ? strtotime($seenAt) : false;
        if ($seenTimestamp !== false) return min($now + $this->retentionSeconds, $seenTimestamp + $this->retentionSeconds);
        return $now + $this->retentionSeconds;
    }

    private function patternIndex(): array
    {
        $index = $this->cache->get($this->indexKey, []);
        return is_array($index) ? array_filter($index, fn ($expiresAt) => (int) $expiresAt > time()) : [];
    }
    private function validPatternKey(string $key): bool { return $key !== '' && strlen($key) <= 200 && preg_match('/^[^\x00-\x1F\x7F]+$/', $key) === 1; }
    private function validFeedbackId(string $id): bool { return $id !== '' && strlen($id) <= 200 && preg_match('/^[^\x00-\x1F\x7F]+$/', $id) === 1; }
    private function patternHash(string $key): string { return hash('sha256', $key); }
    private function cacheKey(string $patternKey): string { return $this->prefix . $this->patternHash($patternKey); }
    private function processedKey(string $feedbackId): string { return $this->prefix . 'processed:' . hash('sha256', $feedbackId); }
    private function counterKey(string $patternKey, string $outcome): string { return $this->prefix . 'counter:' . hash('sha256', $patternKey . ':' . $outcome); }
}
