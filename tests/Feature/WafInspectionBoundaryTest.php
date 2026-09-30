<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature;

use Mixudev\SecurityDefense\Rules\PathReconnaissanceRule;
use Mixudev\SecurityDefense\Rules\PayloadInjectionRule;
use Mixudev\SecurityDefense\Tests\TestCase;

/**
 * Two WAF hardening properties that a green suite cannot detect on its own:
 *
 *  1. PathReconnaissanceRule used a bare substring match, so legitimate
 *     commerce URLs containing "console", "actuator" or "server-status" were
 *     treated as reconnaissance. Boundaries are required.
 *  2. PayloadInjectionRule truncated oversized input to its PREFIX only, so an
 *     attacker could push a payload past max_inspection_length and be scanned
 *     clean. Both edges must be inspected.
 */
class WafInspectionBoundaryTest extends TestCase
{
    public function test_legitimate_paths_are_not_flagged_as_reconnaissance(): void
    {
        $rule = app(PathReconnaissanceRule::class);

        foreach ([
            'store/gaming/nintendo-switch-console',
            'store/industrial/valve-actuator-model-5',
            'admin/server-status-monitor-device',
            'products/console-table-accessories',
        ] as $path) {
            $this->assertFalse(
                $rule->isSensitivePath($path),
                "Path produk yang sah '{$path}' tidak boleh dianggap reconnaissance."
            );
        }
    }

    public function test_real_reconnaissance_paths_are_still_flagged(): void
    {
        $rule = app(PathReconnaissanceRule::class);

        foreach ([
            'actuator',
            'actuator/health',
            'actuator/env',
            'api/actuator/beans',
            'console',
            'admin/console',
            'server-status',
            'nginx/server-status',
        ] as $path) {
            $this->assertTrue(
                $rule->isSensitivePath($path),
                "Path reconnaissance nyata '{$path}' harus tetap terdeteksi."
            );
        }
    }

    public function test_padding_cannot_hide_a_payload_from_inspection(): void
    {
        $rule = app(PayloadInjectionRule::class);
        $payload = "' UNION SELECT 1,2,3--";
        $limit = (int) config('security-defense.hardening.max_inspection_length', 4096);

        $this->assertTrue($rule->inspect(['q' => $payload])['matched'], 'Payload polos harus terdeteksi.');

        $prefixPadded = $rule->inspect(['q' => str_repeat('A', $limit + 200) . $payload]);
        $this->assertTrue(
            $prefixPadded['matched'],
            'Payload setelah padding panjang harus tetap terdeteksi.'
        );

        $suffixPadded = $rule->inspect(['q' => $payload . str_repeat('A', $limit + 200)]);
        $this->assertTrue(
            $suffixPadded['matched'],
            'Payload sebelum padding panjang harus tetap terdeteksi.'
        );
    }

    public function test_inspection_stays_bounded_for_oversized_input(): void
    {
        $rule = app(PayloadInjectionRule::class);
        $limit = (int) config('security-defense.hardening.max_inspection_length', 4096);

        $started = microtime(true);
        $result = $rule->inspect(['q' => str_repeat('select ', 4000)]);
        $elapsed = (microtime(true) - $started) * 1000;

        $this->assertFalse($result['matched'], 'Input bersih yang panjang tidak boleh dianggap payload.');
        $this->assertLessThan(
            1000.0,
            $elapsed,
            'Inspeksi input besar harus tetap terikat waktunya (anti-ReDoS).'
        );
    }
}