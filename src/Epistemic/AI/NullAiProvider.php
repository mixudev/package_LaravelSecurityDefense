<?php
declare(strict_types=1);

namespace Mixudev\SecurityDefense\Epistemic\AI;

use Mixudev\SecurityDefense\Epistemic\Contracts\AiEvidenceProviderInterface;
use Mixudev\SecurityDefense\Epistemic\DTO\AnalysisContext;

/**
 * Default no-op AI provider. Replace by binding a real implementation in ServiceProvider.
 * AI is evidence source only — never decision authority.
 */
final class NullAiProvider implements AiEvidenceProviderInterface
{
    public function getEvidenceFor(AnalysisContext $context): array
    {
        return [];
    }
}
