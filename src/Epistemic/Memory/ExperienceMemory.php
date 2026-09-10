<?php
declare(strict_types=1);

namespace Mixudev\SecurityDefense\Epistemic\Memory;

use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Mixudev\SecurityDefense\Epistemic\Contracts\ExperienceMemoryInterface;

final class ExperienceMemory implements ExperienceMemoryInterface
{
    private string $prefix;
    private int $maxPatterns;
    private int $retentionSeconds;

    public function __construct(private readonly CacheRepository $cache, string $cachePrefix = 'security_defense:', int $maxPatterns = 10000, int $retentionDays = 30)
    {
        $this->prefix = $cachePrefix . 'ep:pattern:';
        $this->maxPatterns = $maxPatterns;
        $this->retentionSeconds = $retentionDays * 86400;
    }

    public function recall(string $patternKey): ?ThreatPattern
    {
        $data = $this->cache->get($this->cacheKey($patternKey));
        if (!is_array($data)) return null;
        return new ThreatPattern(key: $data['key'], confidence: (float) $data['confidence'], truePositiveCount: (int) ($data['tp'] ?? 0), falsePositiveCount: (int) ($data['fp'] ?? 0), lastOutcome: $data['last_outcome'] ?? null, lastSeenAt: $data['last_seen_at'] ?? null);
    }

    public function store(ThreatPattern $pattern): void
    {
        // ponytail: no global pattern count enforced; add when switching to DB backend
        $this->cache->put($this->cacheKey($pattern->key), ['key' => $pattern->key, 'confidence' => $pattern->confidence, 'tp' => $pattern->truePositiveCount, 'fp' => $pattern->falsePositiveCount, 'last_outcome' => $pattern->lastOutcome, 'last_seen_at' => $pattern->lastSeenAt], $this->retentionSeconds);
    }

    public function recordFeedback(string $patternKey, string $outcome): void
    {
        $pattern = $this->recall($patternKey) ?? new ThreatPattern($patternKey, 0.5);
        match ($outcome) { 'confirmed_attack' => $pattern->recordTruePositive(), 'false_positive' => $pattern->recordFalsePositive(), default => null, };
        $this->store($pattern);
    }

    private function cacheKey(string $patternKey): string { return $this->prefix . hash('sha256', $patternKey); }
}
