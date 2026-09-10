<?php
declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Unit\Epistemic;

use DateTimeImmutable;
use Mixudev\SecurityDefense\Epistemic\Belief\ThreatBelief;
use Mixudev\SecurityDefense\Epistemic\Belief\ThreatHypothesis;
use Mixudev\SecurityDefense\Epistemic\Evidence\Evidence;
use Mixudev\SecurityDefense\Epistemic\Feedback\FeedbackHandler;
use Mixudev\SecurityDefense\Epistemic\Memory\ExperienceMemory;
use Mixudev\SecurityDefense\Epistemic\ValueObjects\Confidence;
use Mixudev\SecurityDefense\Epistemic\ValueObjects\EvidenceType;
use Mixudev\SecurityDefense\Tests\TestCase;

class FeedbackHandlerTest extends TestCase
{
    private function makeMemory(): ExperienceMemory
    {
        return new ExperienceMemory(cache: $this->app->make('cache.store'), cachePrefix: 'test_fb:', retentionDays: 1);
    }
    private function makeEvidence(EvidenceType $type, string $id): Evidence { return new Evidence($type, 'test', new DateTimeImmutable(), Confidence::from(0.8), [], $id); }
    private function makeBelief(array $supporting): ThreatBelief { return new ThreatBelief(ThreatHypothesis::ACCOUNT_COMPROMISE, Confidence::from(0.7), $supporting, [], new DateTimeImmutable()); }
    public function test_confirmed_attack_increments_true_positive(): void { $m = $this->makeMemory(); (new FeedbackHandler($m))->record($this->makeBelief([$this->makeEvidence(EvidenceType::LOGIN_FAILED, 'e1'), $this->makeEvidence(EvidenceType::NEW_DEVICE, 'e2')]), 'confirmed_attack'); $p = $m->recall('account_compromise:login_failed+new_device'); $this->assertNotNull($p); $this->assertEquals(1, $p->truePositiveCount); }
    public function test_false_positive_increments_false_positive(): void { $m = $this->makeMemory(); (new FeedbackHandler($m))->record($this->makeBelief([$this->makeEvidence(EvidenceType::OTP_FAILED, 'e3')]), 'false_positive'); $p = $m->recall('account_compromise:otp_failed'); $this->assertNotNull($p); $this->assertEquals(1, $p->falsePositiveCount); }
    public function test_pattern_key_is_deterministic_sorted(): void { $m = $this->makeMemory(); $h = new FeedbackHandler($m); $h->record($this->makeBelief([$this->makeEvidence(EvidenceType::NEW_DEVICE, 'x1'), $this->makeEvidence(EvidenceType::LOGIN_FAILED, 'x2')]), 'confirmed_attack'); $h->record($this->makeBelief([$this->makeEvidence(EvidenceType::LOGIN_FAILED, 'x2'), $this->makeEvidence(EvidenceType::NEW_DEVICE, 'x1')]), 'confirmed_attack'); $p = $m->recall('account_compromise:login_failed+new_device'); $this->assertNotNull($p); $this->assertEquals(2, $p->truePositiveCount); }
}
