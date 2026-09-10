<?php
declare(strict_types=1);

namespace Mixudev\SecurityDefense\Epistemic\Evidence;

final class EvidenceCollection
{
    /** @var array<string, Evidence> keyed by evidence ID for dedup */
    private array $items = [];

    public function add(Evidence $e): void
    {
        $this->items[$e->id] = $e;
    }

    /** @return Evidence[] */
    public function all(): array { return array_values($this->items); }

    /** @return Evidence[] */
    public function supporting(): array
    {
        return array_values(array_filter($this->items, fn(Evidence $e) => $e->isThreatSupporting()));
    }

    /** @return Evidence[] */
    public function contradicting(): array
    {
        return array_values(array_filter($this->items, fn(Evidence $e) => !$e->isThreatSupporting()));
    }

    public function count(): int { return count($this->items); }

    public function hasId(string $id): bool { return isset($this->items[$id]); }
}
