<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Services;

use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Support\Facades\Cache;
use Mixudev\SecurityDefense\DTO\SecurityThreat;

/**
 * Enterprise compound threat scoring engine.
 * Correlates multiple threats from an entity across a sliding window.
 */
class ThreatScoringEngine
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

    protected function getCacheKey(string $target): string
    {
        $prefix = (string) config('security-defense.cache_prefix', 'security_defense:');

        return sprintf('%sscore:%s', $prefix, md5($target));
    }

    public function isEnabled(): bool
    {
        $global = (bool) config('security-defense.enabled', true);
        $scoring = (bool) config('security-defense.detection.scoring.enabled', true);

        return $global && $scoring;
    }

    /**
     * Record a threat against the target entity and evaluate cumulative risk score.
     *
     * @param SecurityThreat $threat
     * @return SecurityThreat|null Returns compound SecurityThreat if score crosses threshold
     */
    public function recordThreat(SecurityThreat $threat): ?SecurityThreat
    {
        if (!$this->isEnabled()) {
            return null;
        }

        // Avoid infinite loop if threat is already a compound threat
        if ($threat->threatType === 'compound_threat') {
            return null;
        }

        $target = (string) ($threat->metadata['ip'] ?? $threat->metadata['target'] ?? $threat->metadata['identifier'] ?? '');
        if ($target === '') {
            return null;
        }

        $window = (int) config('security-defense.detection.scoring.window', 900);
        $threshold = (int) config('security-defense.detection.scoring.threshold', 100);

        $weights = (array) config('security-defense.detection.scoring.weights', []);
        $weight = (int) ($weights[$threat->threatType] ?? match (strtolower($threat->severity)) {
            'critical' => 50,
            'high' => 35,
            'medium' => 20,
            default => 10,
        });

        $cache = $this->getCache();
        $cacheKey = $this->getCacheKey($target);
        $now = time();

        /** @var array<array{score: int, threat: string, time: int}> $records */
        $records = (array) $cache->get($cacheKey, []);
        $records = array_filter(
            $records,
            static fn (array $entry): bool => ($now - (int) ($entry['time'] ?? 0)) <= $window
        );

        $records[] = [
            'score' => $weight,
            'threat' => $threat->threatType,
            'time' => $now,
        ];

        $totalScore = array_sum(array_column($records, 'score'));
        $cache->put($cacheKey, $records, $window);

        if ($totalScore >= $threshold) {
            $fingerprint = hash('sha256', sprintf('compound_threat:%s', strtolower($target)));
            $involvedThreats = array_values(array_unique(array_column($records, 'threat')));

            return new SecurityThreat(
                severity: 'critical',
                threatType: 'compound_threat',
                fingerprint: $fingerprint,
                metadata: [
                    'target' => $target,
                    'aggregate_score' => $totalScore,
                    'threshold' => $threshold,
                    'window_seconds' => $window,
                    'threat_count' => count($records),
                    'involved_threats' => $involvedThreats,
                    'last_trigger_threat' => $threat->threatType,
                ],
                ruleIdentifier: 'threat_scoring_engine'
            );
        }

        return null;
    }

    /**
     * Get current accumulated score for an entity.
     */
    public function getScore(string $target): int
    {
        $cacheKey = $this->getCacheKey($target);
        /** @var array<array{score: int, time: int}> $records */
        $records = (array) $this->getCache()->get($cacheKey, []);
        $window = (int) config('security-defense.detection.scoring.window', 900);
        $now = time();

        $validRecords = array_filter(
            $records,
            static fn (array $entry): bool => ($now - (int) ($entry['time'] ?? 0)) <= $window
        );

        return (int) array_sum(array_column($validRecords, 'score'));
    }

    /**
     * Reset score for a target entity.
     */
    public function resetScore(string $target): void
    {
        $this->getCache()->forget($this->getCacheKey($target));
    }
}
