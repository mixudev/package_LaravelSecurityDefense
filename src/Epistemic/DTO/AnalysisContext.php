<?php
declare(strict_types=1);

namespace Mixudev\SecurityDefense\Epistemic\DTO;

final class AnalysisContext
{
    public function __construct(public readonly array $events = [], public readonly array $evidence = [], public readonly string $subject = '', public readonly int $windowSeconds = 900) {}
}
