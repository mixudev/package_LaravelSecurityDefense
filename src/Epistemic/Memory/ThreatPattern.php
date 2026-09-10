<?php
declare(strict_types=1);

namespace Mixudev\SecurityDefense\Epistemic\Memory;

final class ThreatPattern
{
    public function __construct(public readonly string $key, public float $confidence, public int $truePositiveCount = 0, public int $falsePositiveCount = 0, public ?string $lastOutcome = null, public ?string $lastSeenAt = null) {}
    public function precision(): float { $total = $this->truePositiveCount + $this->falsePositiveCount; return $total > 0 ? $this->truePositiveCount / $total : 0.5; }
    public function recordTruePositive(): void { $this->truePositiveCount++; $this->lastOutcome = 'confirmed_attack'; $this->lastSeenAt = gmdate(DATE_ATOM); $this->confidence = min(1.0, $this->confidence + 0.02); }
    public function recordFalsePositive(): void { $this->falsePositiveCount++; $this->lastOutcome = 'false_positive'; $this->lastSeenAt = gmdate(DATE_ATOM); $this->confidence = max(0.0, $this->confidence - 0.05); }
}
