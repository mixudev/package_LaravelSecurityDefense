<?php
declare(strict_types=1);

namespace Mixudev\SecurityDefense\Epistemic\Contracts;

use Mixudev\SecurityDefense\Epistemic\Evidence\Evidence;
use Mixudev\SecurityDefense\Epistemic\ValueObjects\Confidence;

interface EpistemicEngineInterface
{
    /**
     * @param Evidence[] $supporting
     * @param Evidence[] $contradicting
     */
    public function computeConfidence(array $supporting, array $contradicting): Confidence;
}
