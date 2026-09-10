<?php
declare(strict_types=1);

namespace Mixudev\SecurityDefense\Epistemic\Graph;

final class GraphEdge
{
    public function __construct(
        public readonly string $fromId,
        public readonly string $toId,
        public readonly string $relation,
        public readonly int    $occurredAt,
    ) {}
}
