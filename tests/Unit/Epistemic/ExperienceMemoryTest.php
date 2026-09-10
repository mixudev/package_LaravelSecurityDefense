<?php
declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Unit\Epistemic;

use Mixudev\SecurityDefense\Epistemic\Memory\ExperienceMemory;
use Mixudev\SecurityDefense\Epistemic\Memory\ThreatPattern;
use Mixudev\SecurityDefense\Tests\TestCase;

class ExperienceMemoryTest extends TestCase
{
    private function makeMemory(): ExperienceMemory
    {
        return new ExperienceMemory(cache: $this->app->make('cache.store'), cachePrefix: 'test_sd:', retentionDays: 1);
    }
    public function test_recall_unknown_returns_null(): void { $this->assertNull($this->makeMemory()->recall('nonexistent_key')); }
    public function test_store_and_recall_roundtrip(): void { $m = $this->makeMemory(); $m->store(new ThreatPattern('test:key', 0.7, 2, 1, 'confirmed_attack')); $r = $m->recall('test:key'); $this->assertNotNull($r); $this->assertEqualsWithDelta(0.7, $r->confidence, 0.0001); $this->assertEquals(2, $r->truePositiveCount); $this->assertEquals(1, $r->falsePositiveCount); }
    public function test_record_feedback_confirmed_attack(): void { $m = $this->makeMemory(); $m->recordFeedback('pattern:a', 'confirmed_attack'); $p = $m->recall('pattern:a'); $this->assertNotNull($p); $this->assertEquals(1, $p->truePositiveCount); $this->assertEquals(0, $p->falsePositiveCount); }
    public function test_record_feedback_false_positive(): void { $m = $this->makeMemory(); $m->recordFeedback('pattern:b', 'false_positive'); $p = $m->recall('pattern:b'); $this->assertNotNull($p); $this->assertEquals(0, $p->truePositiveCount); $this->assertEquals(1, $p->falsePositiveCount); $this->assertLessThan(0.5, $p->confidence); }
    public function test_confidence_clamped_after_many_false_positives(): void { $m = $this->makeMemory(); for ($i = 0; $i < 20; $i++) $m->recordFeedback('pattern:fp_many', 'false_positive'); $p = $m->recall('pattern:fp_many'); $this->assertGreaterThanOrEqual(0.0, $p->confidence); $this->assertLessThanOrEqual(1.0, $p->confidence); }
    public function test_unknown_outcome_is_noop(): void { $m = $this->makeMemory(); $m->recordFeedback('pattern:x', 'unknown_whatever'); $p = $m->recall('pattern:x'); $this->assertNotNull($p); $this->assertEquals(0, $p->truePositiveCount); $this->assertEquals(0, $p->falsePositiveCount); }
}
