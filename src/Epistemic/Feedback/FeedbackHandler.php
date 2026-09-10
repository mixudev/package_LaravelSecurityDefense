<?php
declare(strict_types=1);

namespace Mixudev\SecurityDefense\Epistemic\Feedback;

use Mixudev\SecurityDefense\Epistemic\Belief\ThreatBelief;
use Mixudev\SecurityDefense\Epistemic\Memory\ExperienceMemory;

final class FeedbackHandler
{
    public function __construct(private readonly ExperienceMemory $memory) {}
    public function record(ThreatBelief $belief, string $outcome): void { $this->memory->recordFeedback($this->patternKey($belief), $outcome); }
    private function patternKey(ThreatBelief $belief): string { $types = array_map(fn($e) => $e->type->value, $belief->supportingEvidence); sort($types); return $belief->hypothesis->value . ':' . implode('+', $types); }
}
