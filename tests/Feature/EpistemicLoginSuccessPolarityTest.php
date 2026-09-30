<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature;

use DateTimeImmutable;
use Mixudev\SecurityDefense\Epistemic\Correlation\ThreatCorrelator;
use Mixudev\SecurityDefense\Epistemic\Evidence\Evidence;
use Mixudev\SecurityDefense\Epistemic\ValueObjects\Confidence;
use Mixudev\SecurityDefense\Epistemic\ValueObjects\EvidenceType;
use Mixudev\SecurityDefense\Tests\TestCase;

/**
 * Regression: `EvidenceType::LOGIN_SUCCESS` was omitted from the benign/contradicting
 * list in `Evidence::isThreatSupporting()`, and was fell through to `UNKNOWN` in
 * `ThreatCorrelator`.
 *
 * As a result, a single successful login was treated as supporting evidence for a
 * threat, driving risk to 0.998 and producing an epistemic decision to BLOCK the
 * user.
 *
 * `LOGIN_SUCCESS` is now classified as contradicting evidence under the
 * `ACCOUNT_COMPROMISE` hypothesis, so legitimate logins actively reduce
 * compromise confidence rather than triggering defense action.
 */
final class EpistemicLoginSuccessPolarityTest extends TestCase
{
    public function test_login_success_is_classified_as_contradicting_not_threat_supporting(): void
    {
        $loginSuccess = new Evidence(
            type: EvidenceType::LOGIN_SUCCESS,
            source: 'auth',
            occurredAt: new DateTimeImmutable(),
            reliability: Confidence::from(0.9),
        );

        self::assertFalse(
            $loginSuccess->isThreatSupporting(),
            'LOGIN_SUCCESS was evaluated as threat-supporting evidence; legitimate logins '
            . 'must contradict account compromise hypotheses, not support them'
        );
    }

    public function test_single_login_success_does_not_emit_an_unknown_threat_belief(): void
    {
        $loginSuccess = new Evidence(
            type: EvidenceType::LOGIN_SUCCESS,
            source: 'auth',
            occurredAt: new DateTimeImmutable(),
            reliability: Confidence::from(0.9),
        );

        $beliefs = (new ThreatCorrelator())->correlate([$loginSuccess]);

        self::assertEmpty(
            $beliefs,
            'A single legitimate login emitted an actionable threat belief'
        );
    }
}
