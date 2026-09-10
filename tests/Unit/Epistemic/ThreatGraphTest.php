<?php
declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Unit\Epistemic;

use Mixudev\SecurityDefense\Epistemic\Graph\GraphEdge;
use Mixudev\SecurityDefense\Epistemic\Graph\GraphNode;
use Mixudev\SecurityDefense\Epistemic\Graph\ThreatGraph;
use PHPUnit\Framework\TestCase;

class ThreatGraphTest extends TestCase
{
    private function node(string $id): GraphNode
    {
        return new GraphNode($id, 'test', $id);
    }

    private function edge(string $from, string $to): GraphEdge
    {
        return new GraphEdge($from, $to, 'RELATED_TO', time());
    }

    public function test_add_node_returns_true(): void
    {
        $g = new ThreatGraph();
        $this->assertTrue($g->addNode($this->node('A')));
    }

    public function test_add_node_returns_false_at_cap(): void
    {
        $g = new ThreatGraph(2);
        $g->addNode($this->node('A'));
        $g->addNode($this->node('B'));
        $this->assertFalse($g->addNode($this->node('C')));
    }

    public function test_reachable_from_basic(): void
    {
        $g = new ThreatGraph();
        $g->addNode($this->node('A'));
        $g->addNode($this->node('B'));
        $g->addNode($this->node('C'));
        $g->addEdge($this->edge('A', 'B'));
        $g->addEdge($this->edge('B', 'C'));

        $result = $g->reachableFrom('A');
        $ids = array_map(fn($n) => $n->id, $result);
        $this->assertContains('A', $ids);
        $this->assertContains('B', $ids);
        $this->assertContains('C', $ids);
    }

    public function test_cycle_does_not_loop_forever(): void
    {
        $g = new ThreatGraph();
        $g->addNode($this->node('A'));
        $g->addNode($this->node('B'));
        $g->addNode($this->node('C'));
        $g->addEdge($this->edge('A', 'B'));
        $g->addEdge($this->edge('B', 'C'));
        $g->addEdge($this->edge('C', 'A'));

        $result = $g->reachableFrom('A');
        $this->assertCount(3, $result);
    }

    public function test_depth_limit_respected(): void
    {
        $g = new ThreatGraph();
        foreach (['A','B','C','D','E'] as $id) {
            $g->addNode($this->node($id));
        }
        $g->addEdge($this->edge('A', 'B'));
        $g->addEdge($this->edge('B', 'C'));
        $g->addEdge($this->edge('C', 'D'));
        $g->addEdge($this->edge('D', 'E'));

        $result = $g->reachableFrom('A', 2);
        $ids = array_map(fn($n) => $n->id, $result);
        $this->assertContains('A', $ids);
        $this->assertContains('B', $ids);
        $this->assertContains('C', $ids);
        $this->assertNotContains('D', $ids);
        $this->assertNotContains('E', $ids);
    }

    public function test_edge_silently_skipped_if_node_missing(): void
    {
        $g = new ThreatGraph();
        $g->addNode($this->node('A'));
        $g->addEdge($this->edge('A', 'B'));
        $this->assertTrue(true);
    }

    public function test_node_count(): void
    {
        $g = new ThreatGraph();
        $g->addNode($this->node('X'));
        $g->addNode($this->node('Y'));
        $this->assertEquals(2, $g->nodeCount());
    }
}
