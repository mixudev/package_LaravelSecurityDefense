<?php
declare(strict_types=1);

namespace Mixudev\SecurityDefense\Epistemic\DTO;

final class AnalysisContext
{
    public readonly array $events;
    public readonly array $evidence;
    public readonly string $subject;
    public readonly int $windowSeconds;

    public function __construct(array $events = [], array $evidence = [], string $subject = '', int $windowSeconds = 900)
    {
        // Analyzer applies configured limits. Keep DTO free of deployment policy.
        $this->events = $events;
        $this->evidence = $evidence;
        $this->subject = $subject;
        $this->windowSeconds = $windowSeconds;
    }
}
