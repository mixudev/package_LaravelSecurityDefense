<?php
declare(strict_types=1);

namespace Mixudev\SecurityDefense\Epistemic\Feedback;

use InvalidArgumentException;
use Mixudev\SecurityDefense\Epistemic\Belief\ThreatBelief;
use Mixudev\SecurityDefense\Epistemic\Contracts\ExperienceMemoryInterface;

final class FeedbackHandler
{
    private const ALLOWED_OUTCOMES = ['confirmed_attack', 'false_positive'];

    public function __construct(private readonly ExperienceMemoryInterface $memory) {}

    public function record(ThreatBelief $belief, string $outcome, ?string $feedbackId = null): void
    {
        if (!in_array($outcome, self::ALLOWED_OUTCOMES, true)) {
            throw new InvalidArgumentException('Unsupported feedback outcome.');
        }

        $this->memory->recordFeedback($this->patternKey($belief), $outcome, $feedbackId);
    }
    private function patternKey(ThreatBelief $belief): string { $types = array_map(fn($e) => $e->type->value, $belief->supportingEvidence); sort($types); return $belief->hypothesis->value . ':' . implode('+', $types); }
}
