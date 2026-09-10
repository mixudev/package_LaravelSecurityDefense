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
    public function test_unknown_outcome_is_noop_without_creating_pattern(): void { $m = $this->makeMemory(); $m->recordFeedback('pattern:x', 'unknown_whatever'); $this->assertNull($m->recall('pattern:x')); }
    public function test_legacy_record_without_expires_at_is_readable(): void { $m = $this->makeMemory(); $this->app->make('cache.store')->forever('test_sd:ep:pattern:' . hash('sha256', 'legacy:key'), ['key' => 'legacy:key', 'confidence' => 0.6, 'tp' => 3, 'fp' => 1, 'last_outcome' => 'confirmed_attack']); $r = $m->recall('legacy:key'); $this->assertNotNull($r); $this->assertEqualsWithDelta(0.6, $r->confidence, 0.0001); $this->assertEquals(3, $r->truePositiveCount); $this->assertEquals(1, $r->falsePositiveCount); }
    public function test_legacy_record_without_expires_at_is_backdated_not_immortal(): void { $m = $this->makeMemory(); $this->app->make('cache.store')->forever('test_sd:ep:pattern:' . hash('sha256', 'legacy:stale'), ['key' => 'legacy:stale', 'confidence' => 0.6, 'tp' => 3, 'fp' => 1, 'last_outcome' => 'confirmed_attack', 'last_seen_at' => gmdate(DATE_ATOM, time() - 86400 * 30)]); $this->assertNull($m->recall('legacy:stale')); }
    public function test_max_patterns_bounds_new_keys(): void { $m = new ExperienceMemory($this->app->make('cache.store'), 'bounded:', 1, 1); $m->store(new ThreatPattern('one', 0.5)); $m->store(new ThreatPattern('two', 0.5)); $this->assertNotNull($m->recall('one')); $this->assertNull($m->recall('two')); }
    public function test_invalid_pattern_key_is_ignored(): void { $m = $this->makeMemory(); $m->recordFeedback(str_repeat('x', 201), 'confirmed_attack'); $this->assertNull($m->recall(str_repeat('x', 201))); }
    public function test_feedback_id_is_idempotent(): void { $m = $this->makeMemory(); $m->recordFeedback('same', 'confirmed_attack', 'feedback-1'); $m->recordFeedback('same', 'confirmed_attack', 'feedback-1'); $this->assertSame(1, $m->recall('same')->truePositiveCount); }
    public function test_cache_prefix_isolation(): void { $a = new ExperienceMemory($this->app->make('cache.store'), 'prefix-a:', 10, 1); $b = new ExperienceMemory($this->app->make('cache.store'), 'prefix-b:', 10, 1); $a->recordFeedback('same', 'confirmed_attack'); $this->assertNull($b->recall('same')); }
}
