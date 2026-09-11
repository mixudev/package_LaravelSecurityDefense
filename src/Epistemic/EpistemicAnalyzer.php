<?php
declare(strict_types=1);

namespace Mixudev\SecurityDefense\Epistemic;

use DateTimeImmutable;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Mixudev\SecurityDefense\Epistemic\Contracts\AiEvidenceProviderInterface;
use Mixudev\SecurityDefense\Epistemic\Contracts\ExperienceMemoryInterface;
use Mixudev\SecurityDefense\Epistemic\Contracts\PolicyEngineInterface;
use Mixudev\SecurityDefense\Epistemic\Contracts\DecisionResponseAdapterInterface;
use Mixudev\SecurityDefense\Epistemic\Response\ResponseResult;
use Mixudev\SecurityDefense\Epistemic\Correlation\ThreatCorrelator;
use Mixudev\SecurityDefense\Epistemic\DTO\AnalysisContext;
use Mixudev\SecurityDefense\Epistemic\DTO\ThreatAssessment;
use Mixudev\SecurityDefense\Epistemic\Engine\EpistemicEngine;
use Mixudev\SecurityDefense\Epistemic\Engine\RiskEngine;
use Mixudev\SecurityDefense\Epistemic\Evidence\Evidence;
use Mixudev\SecurityDefense\Epistemic\Evidence\EvidenceBuilder;
use Mixudev\SecurityDefense\Epistemic\Evidence\EvidenceCollection;
use Mixudev\SecurityDefense\Epistemic\Graph\GraphEdge;
use Mixudev\SecurityDefense\Epistemic\Graph\GraphNode;
use Mixudev\SecurityDefense\Epistemic\Graph\ThreatGraph;
use Mixudev\SecurityDefense\Epistemic\Memory\ThreatPattern;
use Mixudev\SecurityDefense\Epistemic\ValueObjects\Confidence;
use Mixudev\SecurityDefense\Epistemic\ValueObjects\RiskScore;
use Mixudev\SecurityDefense\DTO\SecurityEvent;

/** Full epistemic analysis pipeline orchestrator. */
final class EpistemicAnalyzer
{
    public function __construct(
        private readonly EpistemicEngine $epistemicEngine,
        private readonly RiskEngine $riskEngine,
        private readonly ThreatCorrelator $correlator,
        private readonly PolicyEngineInterface $policyEngine,
        private readonly AiEvidenceProviderInterface $aiProvider,
        private readonly array $config = [],
        private readonly ?ExperienceMemoryInterface $memory = null,
        private readonly ?DecisionResponseAdapterInterface $responseAdapter = null,
        private readonly ?CacheRepository $cache = null,
    ) {
        $this->responseResults = [];
    }

    /** @var array<string, ResponseResult> */
    private array $responseResults;

    /** @var array<string, true> */
    private array $responseExecutionKeys = [];

    public function responseResult(string $decisionId): ?ResponseResult
    {
        return $this->responseResults[$decisionId] ?? null;
    }

    public function analyze(AnalysisContext $context): ThreatAssessment
    {
        $graph = $this->buildGraph($context);
        $collection = new EvidenceCollection();
        foreach (array_slice($context->events, 0, $this->maxEvents()) as $event) {
            if (!$event instanceof SecurityEvent) continue;
            if (($e = EvidenceBuilder::fromSecurityEvent($event)) !== null) $collection->add($e);
        }
        foreach (array_slice($context->evidence, 0, $this->maxEvidence()) as $e) {
            if ($e instanceof Evidence && $this->isValidDirectEvidence($e)) $collection->add($e);
        }
        foreach ($this->validatedAiEvidence($context) as $e) $collection->add($e);
        $trustedEvidence = array_values(array_filter($collection->all(), fn (Evidence $e) => !$this->isAiEvidence($e)));

        // AI is advisory only: it cannot independently authorize a response.
        $correlationEvidence = $trustedEvidence;
        if (count($trustedEvidence) >= 2) {
            $correlationEvidence = array_merge($trustedEvidence, array_values(array_filter(
                $collection->all(), fn (Evidence $e) => $this->isAiEvidence($e)
            )));
        }
        $beliefs = $this->correlator->correlate($correlationEvidence, $context->windowSeconds);
        if (count($trustedEvidence) < 2 && count($trustedEvidence) < $collection->count()) {
            $beliefs = [];
        }
        $computedBeliefs = [];
        $maxRisk = RiskScore::zero();
        foreach ($beliefs as $belief) {
            $confidence = $this->epistemicEngine->computeConfidence(
                $belief->supportingEvidence, $belief->contradictingEvidence
            );
            $pattern = $this->recallPattern($context, $belief->hypothesis->value);
            $adjustment = $this->memoryAdjustment($pattern);
            // Graph signal stays bounded and cannot override evidence-derived confidence.
            if ($graph->nodeCount() > 1 && count($graph->reachableFrom($this->subjectNodeId($context), (int) ($this->config['graph']['max_depth'] ?? 8))) > 1) {
                $adjustment += 0.02;
            }
            $confidence = Confidence::from(max(0.0, min(1.0, $confidence->toFloat() + $adjustment)));
            $belief = $belief->withConfidence($confidence);
            $risk = $this->riskEngine->calculate($belief, RiskScore::zero(), $this->config['risk'] ?? []);
            if ($adjustment !== 0.0) {
                $risk = RiskScore::from(max(0.0, min(1.0, $risk->toFloat() + $adjustment)));
            }
            if ($risk->isHigherThan($maxRisk)) $maxRisk = $risk;
            $computedBeliefs[] = $belief;
        }
        $aggConfidence = count($computedBeliefs) > 0
            ? Confidence::from(array_sum(array_map(fn($b) => $b->confidence->toFloat(), $computedBeliefs)) / count($computedBeliefs))
            : Confidence::from(0.0);
        $assessment = new ThreatAssessment(risk: $maxRisk, confidence: $aggConfidence, hypotheses: $computedBeliefs, evidence: $collection->all());
        $aiPresent = count($trustedEvidence) < $collection->count();
        $decision = ($collection->count() > 0 && ($trustedEvidence === [] || ($aiPresent && count($trustedEvidence) < 2)))
            ? null
            : $this->policyEngine->decide($assessment);
        if (($this->config['response']['enabled'] ?? false) && $this->responseAdapter !== null && $decision !== null) {
            $decisionId = $decision->id();
            $executionKey = $this->responseExecutionKey($decisionId, $decision, $context, $collection);
            $cacheClaimed = $this->tryClaimExecutionKey($executionKey);
            if ($cacheClaimed) {
                try {
                    $this->responseResults[$decisionId] = $this->responseAdapter->respond($decision);
                } catch (\Throwable) {
                    // Single attempt only. Adapters may produce non-idempotent
                    // side effects; retrying could duplicate them. Explicit
                    // idempotent adapters should handle their own retry policy.
                    $this->responseResults[$decisionId] = new ResponseResult(false, $decisionId, 'Response adapter failed.');
                }
            }
        }
        $assessment = new ThreatAssessment(risk: $maxRisk, confidence: $aggConfidence, hypotheses: $computedBeliefs, evidence: $collection->all(), decision: $decision);
        $this->publishDashboardSnapshot($assessment);
        return $assessment;
    }

    private function publishDashboardSnapshot(ThreatAssessment $assessment): void
    {
        if ($this->cache === null) return;

        $cachePrefix = (string) ($this->config['cache_prefix'] ?? config('security-defense.cache_prefix', 'security_defense:'));
        $this->cache->put($cachePrefix . 'epistemic:last_analysis', [
            'risk' => $assessment->risk->toFloat(),
            'confidence' => $assessment->confidence->toFloat(),
            'hypotheses' => array_map(function ($belief) use ($assessment): array {
                return [
                    'hypothesis' => $belief->hypothesis->value,
                    'confidence' => $belief->confidence->toFloat(),
                    'risk' => $assessment->risk->toFloat(),
                    'supporting' => array_map(fn ($e) => $e->type->value, $belief->supportingEvidence),
                    'contradicting' => array_map(fn ($e) => $e->type->value, $belief->contradictingEvidence),
                    'action' => $assessment->decision?->action->value ?? 'monitor',
                ];
            }, $assessment->hypotheses),
            'evidence_feed' => array_map(static fn (Evidence $e): array => [
                'type' => $e->type->value,
                'source' => substr($e->source, 0, 128),
                'timestamp' => $e->occurredAt->format(DATE_ATOM),
                'reliability' => $e->reliability->toFloat(),
            ], array_slice($assessment->evidence, 0, 50)),
        ], 300);
    }

    /** @param Evidence[] $all @param Evidence[] $trusted @return Evidence[] */
    private function advisoryAiEvidence(array $all, array $trusted): array
    {
        if ($trusted === []) return [];
        $trustedTypes = array_map(fn (Evidence $e) => $e->type->value, $trusted);
        return array_values(array_filter($all, fn (Evidence $e) => $this->isAiEvidence($e)
            && in_array($e->type->value, $trustedTypes, true)));
    }

    private function responseExecutionKey(string $decisionId, \Mixudev\SecurityDefense\Epistemic\Policy\ThreatDecision $decision, AnalysisContext $context, EvidenceCollection $collection): string
    {
        return 'security-defense:epistemic-response:' . hash('sha256', serialize([$decisionId, $decision->action->value, $decision->reason, $decision->context, $context->subject, $context->windowSeconds, array_map(fn (Evidence $e) => [$e->id, $e->type->value, $e->source, $e->metadata], $collection->all())]));
    }

    private function tryClaimExecutionKey(string $key): bool
    {
        if (isset($this->responseExecutionKeys[$key])) return false;
        if ($this->cache !== null && !$this->cache->add($key, true, (int) ($this->config['response']['dedup_ttl'] ?? 300))) return false;
        $this->responseExecutionKeys[$key] = true;
        return true;
    }

    private function isValidDirectEvidence(Evidence $e): bool
    {
        $cfg = (array) ($this->config['ai'] ?? []);
        $futureSkew = max(0, (int) ($cfg['allowed_future_seconds'] ?? 60));
        $maxMetadata = max(0, (int) ($cfg['max_metadata_bytes'] ?? 4096));
        if ($e->id === '' || $e->source === '' || $e->occurredAt->getTimestamp() > time() + $futureSkew) return false;
        $json = json_encode($e->metadata);
        return $json !== false && strlen($json) <= $maxMetadata;
    }

    /** @return Evidence[] */
    private function validatedAiEvidence(AnalysisContext $context): array
    {
        $cfg = (array) ($this->config['ai'] ?? []);
        $max = max(0, (int) ($cfg['max_evidence'] ?? 20));
        $maxMetadata = max(0, (int) ($cfg['max_metadata_bytes'] ?? 4096));
        $futureSkew = max(0, (int) ($cfg['allowed_future_seconds'] ?? 60));
        try {
            $items = $this->aiProvider->getEvidenceFor($context);
        } catch (\Throwable) {
            return [];
        }
        if (!is_array($items)) return [];
        $valid = [];
        $now = time();
        foreach (array_slice($items, 0, $max) as $e) {
            if (!$e instanceof Evidence || $e->id === '' || $e->source === '' || !str_starts_with($e->source, 'ai')) continue;
            if (!isset($e->metadata['provenance']) || !is_string($e->metadata['provenance']) || $e->metadata['provenance'] === '') continue;
            if ($e->occurredAt->getTimestamp() > $now + $futureSkew) continue;
            $json = json_encode($e->metadata);
            if ($json === false || strlen($json) > $maxMetadata) continue;
            $valid[] = $e;
        }
        return $valid;
    }

    private function maxEvents(): int
    {
        return max(0, (int) (($this->config['limits']['max_events'] ?? 500)));
    }

    private function maxEvidence(): int
    {
        return max(0, (int) (($this->config['limits']['max_evidence'] ?? 500)));
    }

    private function isAiEvidence(Evidence $e): bool
    {
        return str_starts_with($e->source, 'ai');
    }

    private function buildGraph
(AnalysisContext $context): ThreatGraph
    {
        $cfg = (array) ($this->config['graph'] ?? []);
        $now = time();
        $graph = new ThreatGraph(
            (int) ($cfg['max_nodes'] ?? 500),
            (int) ($cfg['max_edges'] ?? 1000),
            max(0, (int) ($cfg['max_future_skew'] ?? 60)),
        );
        $subjectId = $this->subjectNodeId($context);
        $graph->addNode(new GraphNode($subjectId, 'subject', substr($context->subject, 0, 256)));
        $windowStart = $now - max(1, (int) ($cfg['window_seconds'] ?? $context->windowSeconds));
        $previousId = $subjectId;
        foreach (array_slice($context->events, 0, (int) ($cfg['max_nodes'] ?? 500)) as $i => $event) {
            if (!$event instanceof SecurityEvent) continue;
            $id = 'event:' . $i . ':' . hash('sha256', serialize($event));
            if (!$this->addGraphNode($graph, new GraphNode($id, 'event', substr((string) ($event->eventType ?? 'event'), 0, 256)))) break;
            $occurredAt = $this->eventTimestamp($event);
            if ($occurredAt >= $windowStart && $occurredAt <= $now) {
                $graph->addEdge(new GraphEdge($previousId, $id, 'RELATED_TO', $occurredAt));
                $previousId = $id;
            }
        }
        foreach (array_slice($context->evidence, 0, (int) ($cfg['max_nodes'] ?? 500)) as $evidence) {
            if (!$evidence instanceof Evidence) continue;
            $id = 'evidence:' . $evidence->id;
            if (!$this->addGraphNode($graph, new GraphNode($id, 'evidence', substr($evidence->type->value, 0, 256))) ) break;
            $occurredAt = $evidence->occurredAt->getTimestamp();
            if ($occurredAt >= $windowStart && $occurredAt <= $now) $graph->addEdge(new GraphEdge($previousId, $id, 'SUPPORTS', $occurredAt));
        }
        return $graph;
    }

    private function addGraphNode(ThreatGraph $graph, GraphNode $node): bool
    {
        return $graph->hasNode($node->id) || $graph->addNode($node);
    }

    private function subjectNodeId(AnalysisContext $context): string
    {
        return 'subject:' . hash('sha256', substr($context->subject, 0, 256));
    }

    private function eventTimestamp(object $event): int
    {
        try { return (new DateTimeImmutable((string) ($event->timestamp ?? 'now')))->getTimestamp(); }
        catch (\Throwable) { return 0; }
    }

    private function recallPattern(AnalysisContext $context, string $hypothesis): ?ThreatPattern
    {
        if ($this->memory === null || $context->subject === '') return null;
        return $this->memory->recall($context->subject . ':' . $hypothesis)
            ?? $this->memory->recall($context->subject);
    }

    private function memoryAdjustment(?ThreatPattern $pattern): float
    {
        if ($pattern === null) return 0.0;
        $signal = (($pattern->confidence + $pattern->precision()) / 2.0) - 0.5;
        return max(-0.10, min(0.10, $signal * 0.20));
    }
}
