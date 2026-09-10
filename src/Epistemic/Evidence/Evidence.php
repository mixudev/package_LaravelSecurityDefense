<?php
declare(strict_types=1);

namespace Mixudev\SecurityDefense\Epistemic\Evidence;

use DateTimeImmutable;
use Mixudev\SecurityDefense\Epistemic\ValueObjects\Confidence;
use Mixudev\SecurityDefense\Epistemic\ValueObjects\EvidenceType;

final class Evidence
{
    public readonly string $id;

    /** Evidence construction bounds — applied uniformly to all sources. */
    private const MAX_METADATA_BYTES = 4096;
    private const FUTURE_SKEW_SECONDS = 300;  // 5 min
    private const PAST_BOUND_SECONDS = 86400 * 365; // 1 year

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
        // Validate inputs at trust boundary.
        if ($source === '') throw new \InvalidArgumentException('Evidence source must not be empty');
        if (strlen($source) > 128) throw new \InvalidArgumentException('Evidence source exceeds 128 chars');
        $json = json_encode($metadata);
        if ($json !== false && strlen($json) > self::MAX_METADATA_BYTES) {
            throw new \InvalidArgumentException(sprintf('Evidence metadata exceeds %d bytes', self::MAX_METADATA_BYTES));
        }
        if ($id !== null && $id !== '') {
            $this->id = $id;
            return;
        }

        $canonicalMetadata = $metadata;
        $this->sortMetadata($canonicalMetadata);
        $metadataJson = json_encode($canonicalMetadata, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        $identity = implode(':', [
            $type->value,
            $source,
            $occurredAt->format('Y-m-d\\TH:i:s.uP'),
            hash('sha256', $metadataJson === false ? '' : $metadataJson),
        ]);
        $this->id = hash('sha256', $identity);
    }

    /** @param array<string, mixed> $metadata */
    private function sortMetadata(array &$metadata, int $depth = 0): void
    {
        if ($depth > 4) {
            $metadata = ['__truncated' => true];
            return;
        }
        ksort($metadata);
        foreach ($metadata as &$value) {
            if (is_array($value)) {
                $this->sortMetadata($value, $depth + 1);
            } elseif (!is_scalar($value) && $value !== null) {
                $value = get_debug_type($value);
            }
        }
        unset($value);
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
