<?php
declare(strict_types=1);

namespace Mixudev\SecurityDefense\Epistemic\Contracts;

use Mixudev\SecurityDefense\Epistemic\DTO\AnalysisContext;
use Mixudev\SecurityDefense\Epistemic\Evidence\Evidence;

interface AiEvidenceProviderInterface
{
    /**
     * @return Evidence[]  AI is just another evidence source, never authority
     */
    public function getEvidenceFor(AnalysisContext $context): array;
}
