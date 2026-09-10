<?php
declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature\Epistemic;

use Mixudev\SecurityDefense\DTO\SecurityEvent;
use Mixudev\SecurityDefense\Services\SecurityDefenseManager;
use Mixudev\SecurityDefense\Tests\TestCase;

class EpistemicBackwardCompatibilityTest extends TestCase
{
    public function test_record_still_works_with_array(): void
    {
        $manager = $this->app->make(SecurityDefenseManager::class);
        $threats = $manager->record([
            'ip' => '127.0.0.1',
            'identifier' => 'test_user',
            'eventType' => 'LoginFailed',
        ]);
        $this->assertIsArray($threats);
    }

    public function test_record_still_works_with_security_event(): void
    {
        $manager = $this->app->make(SecurityDefenseManager::class);
        $event = new SecurityEvent('127.0.0.1', 'test_user', 'LoginFailed');
        $threats = $manager->processEvent($event);
        $this->assertIsArray($threats);
    }

    public function test_analyze_throws_when_epistemic_disabled(): void
    {
        $manager = $this->app->make(SecurityDefenseManager::class);
        $this->expectException(\RuntimeException::class);
        $manager->analyze([]);
    }

    public function test_analyze_works_when_epistemic_enabled(): void
    {
        config()->set('security-defense.epistemic.enabled', true);
        $this->app->forgetInstance(SecurityDefenseManager::class);
        $provider = new \Mixudev\SecurityDefense\Providers\SecurityDefenseServiceProvider($this->app);
        $provider->register();
        $manager = $this->app->make(SecurityDefenseManager::class);
        $assessment = $manager->analyze([]);
        $this->assertEquals(0.0, $assessment->risk()->toFloat());
    }
}
