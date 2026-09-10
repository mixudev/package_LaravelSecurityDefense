<?php
declare(strict_types=1);

namespace Mixudev\SecurityDefense\Epistemic\Belief;

use DateTimeImmutable;
use Mixudev\SecurityDefense\Epistemic\Evidence\Evidence;
use Mixudev\SecurityDefense\Epistemic\ValueObjects\Confidence;

final class ThreatBelief
{
    /**
     * @param Evidence[] $supportingEvidence
     * @param Evidence[] $contradictingEvidence
     */
    public function __construct(
        public readonly ThreatHypothesis  $hypothesis,
        public readonly Confidence        $confidence,
        public readonly array             $supportingEvidence,
        public readonly array             $contradictingEvidence,
        public readonly DateTimeImmutable $updatedAt,
    ) {}

    public function withConfidence(Confidence $confidence): self
    {
        return new self($this->hypothesis, $confidence, $this->supportingEvidence, $this->contradictingEvidence, new DateTimeImmutable());
    }

    public function withAddedSupporting(Evidence $e): self
    {
        return new self($this->hypothesis, $this->confidence, [...$this->supportingEvidence, $e], $this->contradictingEvidence, new DateTimeImmutable());
    }

    public function withAddedContradicting(Evidence $e): self
    {
        return new self($this->hypothesis, $this->confidence, $this->supportingEvidence, [...$this->contradictingEvidence, $e], new DateTimeImmutable());
    }

    public function hasContradiction(): bool
    {
        return count($this->contradictingEvidence) > 0 && count($this->supportingEvidence) > 0;
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'hypothesis' => $this->hypothesis->value,
            'confidence' => $this->confidence->toFloat(),
            'supporting' => array_map(fn(Evidence $e) => $e->type->value, $this->supportingEvidence),
            'contradicting' => array_map(fn(Evidence $e) => $e->type->value, $this->contradictingEvidence),
            'updated_at' => $this->updatedAt->format(DATE_ATOM),
        ];
    }
}
