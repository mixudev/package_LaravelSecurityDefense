<?php
declare(strict_types=1);

namespace Mixudev\SecurityDefense\Epistemic\Correlation;

use DateTimeImmutable;
use Mixudev\SecurityDefense\Epistemic\Belief\ThreatBelief;
use Mixudev\SecurityDefense\Epistemic\Belief\ThreatHypothesis;
use Mixudev\SecurityDefense\Epistemic\Evidence\Evidence;
use Mixudev\SecurityDefense\Epistemic\ValueObjects\Confidence;

final class ThreatCorrelator
{
    /**
     * Minimum supporting evidence required before emitting a belief for each hypothesis.
     * ACCOUNT_COMPROMISE needs ≥2 (e.g. LOGIN_FAILED + NEW_DEVICE).
     * Standalone threats (payload_attack, brute_force, etc.) fire on ≥1.
     * @var array<string, int>
     */
    private const MIN_SUPPORTING = [
        'account_compromise' => 2,
    ];

    /** @return ThreatBelief[] */
    public function correlate(array $evidence, int $windowSeconds = 900): array
    {
        $evidence = TemporalWindow::filter($evidence, $windowSeconds);
        if ($evidence === []) return [];
        $groups = [];
        foreach ($evidence as $item) {
            $hypothesis = match ($item->type->value) {
                'login_failed', 'otp_failed', 'new_device', 'password_reset',
                'trusted_device', 'trusted_location', 'clean_history' => ThreatHypothesis::ACCOUNT_COMPROMISE,
                'brute_force' => ThreatHypothesis::BRUTE_FORCE_ATTACK,
                'payload_injection' => ThreatHypothesis::PAYLOAD_ATTACK,
                'impossible_travel' => ThreatHypothesis::IMPOSSIBLE_TRAVEL,
                'session_anomaly' => ThreatHypothesis::SESSION_HIJACK,
                'behavior_anomaly' => ThreatHypothesis::AUTOMATED_SCRAPING,
                'compound_threat' => ThreatHypothesis::COMPOUND_ATTACK,
                default => ThreatHypothesis::UNKNOWN,
            };
            $key = $hypothesis->value;
            $groups[$key]['hypothesis'] = $hypothesis;
            $groups[$hypothesis->value]['supporting'][] = $item->isThreatSupporting() ? $item : null;
            $groups[$hypothesis->value]['contradicting'][] = $item->isThreatSupporting() ? null : $item;
        }
        $result = [];
        foreach ($groups as $group) {
            $supporting = array_values(array_filter($group['supporting']));
            $hypothesis = $group['hypothesis'];
            $minSupport = self::MIN_SUPPORTING[$hypothesis->value] ?? 1;
            if (count($supporting) < $minSupport) {
                continue;
            }
            $result[] = new ThreatBelief(
                hypothesis: $hypothesis,
                confidence: Confidence::from(0.5),
                supportingEvidence: $supporting,
                contradictingEvidence: array_values(array_filter($group['contradicting'])),
                updatedAt: new DateTimeImmutable(),
            );
        }
        return $result;
    }
}
