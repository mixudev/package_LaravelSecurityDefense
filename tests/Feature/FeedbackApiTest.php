<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature;

use DateTimeImmutable;
use InvalidArgumentException;
use Mixudev\SecurityDefense\Epistemic\Belief\ThreatBelief;
use Mixudev\SecurityDefense\Epistemic\Belief\ThreatHypothesis;
use Mixudev\SecurityDefense\Epistemic\Contracts\ExperienceMemoryInterface;
use Mixudev\SecurityDefense\Epistemic\Evidence\Evidence;
use Mixudev\SecurityDefense\Epistemic\ValueObjects\Confidence;
use Mixudev\SecurityDefense\Epistemic\ValueObjects\EvidenceType;
use Mixudev\SecurityDefense\Services\SecurityDefenseManager;
use Mixudev\SecurityDefense\Support\Facades\SecurityDefense;
use Mixudev\SecurityDefense\Tests\TestCase;
use RuntimeException;

final class FeedbackApiTest extends TestCase
{
    private function belief(): ThreatBelief
    {
        return new ThreatBelief(
            ThreatHypothesis::ACCOUNT_COMPROMISE,
            Confidence::from(0.8),
            [new Evidence(EvidenceType::LOGIN_FAILED, 'test', new DateTimeImmutable(), Confidence::from(0.9), [], 'feedback-e1')],
            [],
            new DateTimeImmutable(),
        );
    }

    public function test_disabled_feedback_rejects_without_creating_memory(): void
    {
        $this->app['config']->set('security-defense.epistemic.enabled', false);
        $manager = $this->app->make(SecurityDefenseManager::class);

        $this->expectException(RuntimeException::class);
        $manager->recordFeedback($this->belief(), 'confirmed_attack', 'disabled-id');
    }

    public function test_enabled_manager_and_facade_record_idempotent_feedback(): void
    {
        $this->app['config']->set('security-defense.epistemic.enabled', true);
        $manager = $this->app->make(SecurityDefenseManager::class);
        $manager->recordFeedback($this->belief(), 'confirmed_attack', 'feedback-1');
        SecurityDefense::recordFeedback($this->belief(), 'confirmed_attack', 'feedback-1');

        $pattern = $this->app->make(ExperienceMemoryInterface::class)->recall('account_compromise:login_failed');
        $this->assertNotNull($pattern);
        $this->assertSame(1, $pattern->truePositiveCount);
    }

    public function test_invalid_outcome_does_not_create_memory(): void
    {
        $this->app['config']->set('security-defense.epistemic.enabled', true);
        $this->expectException(InvalidArgumentException::class);
        SecurityDefense::recordFeedback($this->belief(), 'not-allowed', 'bad-id');
        $this->assertNull($this->app->make(ExperienceMemoryInterface::class)->recall('account_compromise:login_failed'));
    }
}
