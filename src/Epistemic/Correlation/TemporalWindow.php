<?php
declare(strict_types=1);

namespace Mixudev\SecurityDefense\Epistemic\Correlation;

use Mixudev\SecurityDefense\Epistemic\Evidence\Evidence;
use Mixudev\SecurityDefense\Epistemic\ValueObjects\EvidenceType;

final class TemporalWindow
{
    public static function filter(array $evidence, int $windowSeconds, int $allowedClockSkewSeconds = 60, ?int $now = null): array
    {
        $now ??= time();
        $cutoff = $now - $windowSeconds;
        $upperBound = $now + max(0, $allowedClockSkewSeconds);
        return array_values(array_filter(
            $evidence,
            fn(Evidence $e) => $e->occurredAt->getTimestamp() >= $cutoff
                && $e->occurredAt->getTimestamp() <= $upperBound
        ));
    }

    public static function sortChronological(array $evidence): array
    {
        usort($evidence, fn(Evidence $a, Evidence $b) => $a->occurredAt->getTimestamp() <=> $b->occurredAt->getTimestamp());
        return $evidence;
    }

    public static function containsSequence(array $evidence, array $sequence): bool
    {
        $idx = 0; $length = count($sequence);
        foreach ($evidence as $e) { if ($idx >= $length) break; if ($e->type === $sequence[$idx]) $idx++; }
        return $idx >= $length;
    }
}
