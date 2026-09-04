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

    /**
     * Atomic total counter key for an entity's accumulated score.
     * Kept separate from the (bounded) records list so scoring is race-free
     * under concurrent threats at scale.
     */
    protected function getCounterKey(string $target): string
    {
        $prefix = (string) config('security-defense.cache_prefix', 'security_defense:');

        return sprintf('%sscore_total:%s', $prefix, md5($target));
    }

    /**
     * Max threat records retained per entity (metadata only; bounds memory growth).
     */
    protected function maxRecords(): int
    {
        return (int) config('security-defense.detection.scoring.max_records', 50);
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
        $counterKey = $this->getCounterKey($target);
        $now = time();

        // Atomic, race-free total score increment with windowed TTL.
        $totalScore = (int) $cache->increment($counterKey, $weight);
        if ($totalScore === $weight) {
            // First increment seeds the TTL for the accumulation window.
            $cache->put($counterKey, $weight, $window);
        }

        // Bounded records list — metadata only (involved threats), capped to prevent
        // unbounded memory growth in the cache under sustained attack.
        $records = (array) $cache->get($cacheKey, []);
        $records = array_values(array_filter(
            $records,
            static fn (array $entry): bool => ($now - (int) ($entry['time'] ?? 0)) <= $window
        ));
        $records[] = [
            'score' => $weight,
            'threat' => $threat->threatType,
            'time' => $now,
        ];
        if (count($records) > $this->maxRecords()) {
            $records = array_slice($records, -$this->maxRecords());
        }
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
     * Get current accumulated score for an entity (atomic counter read).
     */
    public function getScore(string $target): int
    {
        if (!$this->isEnabled()) {
            return 0;
        }

        return (int) $this->getCache()->get($this->getCounterKey($target), 0);
    }

    /**
     * Reset score for a target entity (clears both atomic counter and records).
     */
    public function resetScore(string $target): void
    {
        $cache = $this->getCache();
        $cache->forget($this->getCounterKey($target));
        $cache->forget($this->getCacheKey($target));
    }
}
