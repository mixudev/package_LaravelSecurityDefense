<?php
declare(strict_types=1);

namespace Mixudev\SecurityDefense\Epistemic\Graph;

final class GraphNode
{
    public function __construct(
        public readonly string $id,
        public readonly string $type,
        public readonly string $value,
        /** @var array<string, mixed> */
        public readonly array  $attributes = [],
    ) {}
}
