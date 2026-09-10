<?php
declare(strict_types=1);

namespace Mixudev\SecurityDefense\Epistemic\Evidence;

use DateTimeImmutable;
use Mixudev\SecurityDefense\Epistemic\ValueObjects\Confidence;
use Mixudev\SecurityDefense\Epistemic\ValueObjects\EvidenceType;

final class Evidence
{
    public readonly string $id;

    /**
     * @param array<string, mixed> $metadata
     */
    public function __construct(
        public readonly EvidenceType      $type,
        public readonly string            $source,
        public readonly DateTimeImmutable $occurredAt,
        public readonly Confidence        $reliability,
        public readonly array             $metadata = [],
        ?string                           $id = null,
    ) {
        $bucket    = $occurredAt->format('YmdHi');
        $this->id  = $id ?? hash('sha256', "{$type->value}:{$source}:{$bucket}");
    }

    /**
     * Freshness: 1.0 when just created, decays linearly to 0.0 over $ttlSeconds.
     */
    public function freshness(int $ttlSeconds, ?DateTimeImmutable $now = null): float
    {
        $now ??= new DateTimeImmutable();
        $age  = max(0, $now->getTimestamp() - $this->occurredAt->getTimestamp());
        return max(0.0, 1.0 - ($age / max(1, $ttlSeconds)));
    }

    /** Whether this evidence supports a threat (vs. contradicts or is neutral). */
    public function isThreatSupporting(): bool
    {
        return !in_array($this->type, [
            EvidenceType::TRUSTED_DEVICE,
            EvidenceType::TRUSTED_LOCATION,
            EvidenceType::CLEAN_HISTORY,
        ], true);
    }
}
