<?php
declare(strict_types=1);

namespace Mixudev\SecurityDefense\Epistemic\Graph;

/**
 * In-memory directed graph. All traversals bounded by depth + node cap.
 * Graph may contain cycles — traversal uses visited set. Always terminates.
 */
final class ThreatGraph
{
    /** @var array<string, GraphNode> */
    private array $nodes = [];

    /** @var array<string, GraphEdge[]> */
    private array $edges = [];

    private int $maxNodes;
    private int $maxEdges;
    private int $maxFutureSkew;
    private int $maxPastAge;
    private int $edgeCount = 0;

    public function __construct(int $maxNodes = 500, int $maxEdges = 1000, int $maxFutureSkew = 60, int $maxPastAge = PHP_INT_MAX)
    {
        $this->maxNodes = max(1, $maxNodes);
        $this->maxEdges = max(0, $maxEdges);
        $this->maxFutureSkew = max(0, $maxFutureSkew);
        $this->maxPastAge = max(0, $maxPastAge);
    }

    public function addNode(GraphNode $node): bool
    {
        if (count($this->nodes) >= $this->maxNodes) {
            return false;
        }
        $this->nodes[$node->id] = $node;
        return true;
    }

    public function addEdge(GraphEdge $edge): void
    {
        if (!isset($this->nodes[$edge->fromId], $this->nodes[$edge->toId])
            || $this->edgeCount >= $this->maxEdges
            || $edge->occurredAt > time() + $this->maxFutureSkew
            || $edge->occurredAt < time() - $this->maxPastAge
        ) {
            return;
        }
        foreach ($this->edges[$edge->fromId] ?? [] as $existing) {
            if ($existing->toId === $edge->toId && $existing->relation === $edge->relation) return;
        }
        $this->edges[$edge->fromId][] = $edge;
        $this->edgeCount++;
    }

    public function hasNode(string $id): bool { return isset($this->nodes[$id]); }

    public function getNode(string $id): ?GraphNode { return $this->nodes[$id] ?? null; }

    public function nodeCount(): int { return count($this->nodes); }

    /** @return GraphNode[] */
    public function reachableFrom(string $startId, int $maxDepth = 8): array
    {
        if (!isset($this->nodes[$startId])) return [];
        $visited = [];
        // Indexed queue: avoids O(n²) array_shift.
        $queue = [[$startId, 0]];
        $head = 0;
        $result = [];
        $len = 1;
        while ($head < $len) {
            [$currentId, $depth] = $queue[$head++];
            if (isset($visited[$currentId]) || $depth > $maxDepth) continue;
            $visited[$currentId] = true;
            $result[] = $this->nodes[$currentId];
            if ($depth < $maxDepth) {
                foreach ($this->edges[$currentId] ?? [] as $edge) {
                    if (!isset($visited[$edge->toId])) {
                        $queue[$len++] = [$edge->toId, $depth + 1];
                    }
                }
            }
        }
        return $result;
    }

    /** @return GraphEdge[] */
    public function edgesFrom(string $nodeId, ?int $windowStart = null): array
    {
        $edges = $this->edges[$nodeId] ?? [];
        if ($windowStart === null) return $edges;
        return array_values(array_filter($edges, fn(GraphEdge $e) => $e->occurredAt >= $windowStart));
    }
}
