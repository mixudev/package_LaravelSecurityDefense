<?php
declare(strict_types=1);

namespace Mixudev\SecurityDefense\Epistemic\Contracts;

use Mixudev\SecurityDefense\Epistemic\Memory\ThreatPattern;

interface ExperienceMemoryInterface
{
    public function recall(string $patternKey): ?ThreatPattern;
    public function store(ThreatPattern $pattern): void;
    public function recordFeedback(string $patternKey, string $outcome, ?string $feedbackId = null): void;
}
