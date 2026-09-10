<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Unit;

use Mixudev\SecurityDefense\DTO\SecurityThreat;
use Mixudev\SecurityDefense\Services\AlertDispatcher;
use Mixudev\SecurityDefense\Tests\TestCase;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Config;

class AlertDispatcherRaceRegressionTest extends TestCase
{
    public function test_rate_limiter_enforces_cap_and_no_overcount(): void
    {
        Config::set('security-defense.hardening.alert_rate_limit.enabled', true);
        Config::set('security-defense.hardening.alert_rate_limit.max_alerts_per_minute', 3);
        Config::set('security-defense.deduplication.enabled', false);

        $dispatcher = app(AlertDispatcher::class);
        $results = [];

        for ($i = 0; $i < 8; $i++) {
            $threat = new SecurityThreat('low', 'brute_force', "rl-fp-{$i}", ['target' => "u{$i}"]);
            $results[] = $dispatcher->dispatch($threat) !== null;
        }

        $emitted = array_filter($results);
        $this->assertCount(3, $emitted, 'Rate limiter must cap at max_alerts_per_minute');
    }

    public function test_nested_metadata_bounded_within_byte_limit(): void
    {
        Config::set('security-defense.hardening.max_alert_metadata_size', 128);
        Config::set('security-defense.hardening.alert_rate_limit.enabled', false);
        Config::set('security-defense.deduplication.enabled', false);

        $dispatcher = app(AlertDispatcher::class);
        $deep = ['l1' => ['l2' => ['l3' => ['l4' => ['l5' => str_repeat('X', 300)]]]]];

        $threat = new SecurityThreat('high', 'brute_force', 'nested-fp', $deep, 'r1');
        $alert = $dispatcher->dispatch($threat);

        $this->assertNotNull($alert, 'Dispatch must succeed');
        $this->assertLessThanOrEqual(128, strlen((string) json_encode($alert->metadata)), 'Nested metadata must respect byte limit');
    }
}
