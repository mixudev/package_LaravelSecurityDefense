<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Unit;

use Illuminate\Contracts\Cache\Repository;
use Illuminate\Cache\ArrayStore;
use Illuminate\Support\Facades\Cache;
use Mixudev\SecurityDefense\DTO\SecurityEvent;
use Mixudev\SecurityDefense\Rules\BehavioralVelocityRule;
use Mixudev\SecurityDefense\Rules\BruteForceRule;
use Mixudev\SecurityDefense\Rules\PathReconnaissanceRule;
use Mixudev\SecurityDefense\Rules\RateLimitBypassRule;
use Mixudev\SecurityDefense\Rules\PayloadInjectionRule;
use Mixudev\SecurityDefense\Services\PayloadDecoder;
use Mixudev\SecurityDefense\Tests\TestCase;

/**
 * Audit batch 1: detection counter atomicity, raw_content detector path,
 * SSRF pattern correctness, and payload decoder bounding.
 */
class CounterInitParityTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        config()->set('security-defense.enabled', true);
        config()->set('security-defense.detection.enabled', true);
        config()->set('security-defense.cache_store', 'array');
        Cache::forgetDriver();
    }

    public function test_window_seed_is_atomic_and_counter_survives_repeat_init(): void
    {
        $event = new SecurityEvent(
            ip: '198.51.100.10',
            identifier: 'victim@example.com',
            eventType: 'LoginFailed'
        );

        /** @var Repository $repo */
        $repo = Cache::store('array');
        $rule = new BruteForceRule($repo);

        $rule->evaluate($event);
        $rule->evaluate($event);
        $rule->evaluate($event);

        // Two requests observed a "fresh" window and re-seeded the counter to 0.
        // They must not lose already-accumulated attempts.
        $counterKey = 'security_defense:rule:brute_force:' . md5('victim@example.com') . ':count';
        $this->assertSame(3, (int) $repo->get($counterKey, 0), 'Counter lost increments across window re-seeds.');
    }

    public function test_all_rule_counters_share_atomic_seed_pattern(): void
    {
        $cases = [
            [
                'rule' => fn (Repository $r) => new BehavioralVelocityRule($r),
                'event' => new SecurityEvent(
                    ip: '198.51.100.11',
                    identifier: 'active_user@example.com',
                    eventType: 'AuthenticatedRequest'
                ),
                'key' => 'security_defense:rule:behavioral_velocity:' . md5('active_user@example.com') . ':velocity:count',
            ],
            [
                'rule' => fn (Repository $r) => new PathReconnaissanceRule($r),
                'event' => new SecurityEvent(
                    ip: '198.51.100.12',
                    identifier: 'anonymous',
                    eventType: 'HttpRequestTelemetry',
                    metadata: ['path' => '/.env']
                ),
                'key' => 'security_defense:rule:path_reconnaissance:probes_count:' . md5('198.51.100.12'),
            ],
            [
                'rule' => fn (Repository $r) => new RateLimitBypassRule($r),
                'event' => new SecurityEvent(
                    ip: '198.51.100.13',
                    identifier: 'anonymous',
                    eventType: 'HttpRequestTelemetry',
                    userAgent: 'Mozilla/5.0'
                ),
                'key' => 'security_defense:rule:rate_limit_bypass:rlb_count:' . md5(sprintf('%s:%s', 'Mozilla/5.0', substr('198.51.100.13', 0, 7))),
            ],
        ];

        foreach ($cases as $index => $case) {
            /** @var Repository $repo */
            $repo = Cache::store('array');
            $rule = $case['rule']($repo);

            $rule->evaluate($case['event']);
            $rule->evaluate($case['event']);
            $rule->evaluate($case['event']);

            $this->assertSame(
                3,
                (int) $repo->get($case['key'], 0),
                'Rule ' . $index . ' counter lost increments across window re-seeds.'
            );
        }
    }

    public function test_raw_content_is_scanned_by_detector_event_path(): void
    {
        config()->set('security-defense.detection.rules.payload_injection.patterns', [
            'sqli' => true,
            'xss' => true,
            'traversal' => true,
            'command_injection' => true,
            'eval_based' => true,
            'php_code_execution' => true,
            'ssrf' => true,
            'ssrf_localhost' => false,
            'xxe' => true,
            'template_injection' => true,
            'crlf_injection' => true,
        ]);

        $event = new SecurityEvent(
            ip: '198.51.100.30',
            identifier: 'guest',
            eventType: 'HttpRequestTelemetry',
            metadata: ['raw_content' => '{"q":"UNION SELECT * FROM users--"}']
        );

        $threat = app(PayloadInjectionRule::class)->evaluate($event);

        $this->assertNotNull($threat, 'Detector must flag payload hidden in raw_content.');
        $this->assertSame('payload_injection', $threat->threatType);
        $this->assertSame('sqli', $threat->metadata['category']);
        $this->assertSame('raw_content', $threat->metadata['matched_field']);
    }

    public function test_ssrf_pattern_matches_standard_private_ranges(): void
    {
        config()->set('security-defense.detection.rules.payload_injection.patterns', [
            'ssrf' => true,
            'ssrf_localhost' => false,
        ]);

        $rule = app(PayloadInjectionRule::class);

        // Never allows a normally-configured LAN target to pass untouched.
        $vectors = [
            'http://192.168.1.1/admin',
            'http://192.168.0.1:8080/config',
            'http://10.0.0.5/internal',
            'http://172.16.0.9/secret',
            'http://169.254.169.254/latest/meta-data/',
            'gopher://internal:70/file',
        ];

        foreach ($vectors as $vector) {
            $hit = $rule->inspect($vector);
            $this->assertTrue($hit['matched'], "SSRF vector not detected: {$vector}");
            $this->assertSame('ssrf', $hit['category'], "Wrong category for: {$vector}");
        }
    }

    public function test_clean_large_json_body_is_not_false_positive(): void
    {
        config()->set('security-defense.detection.rules.payload_injection.patterns', [
            'sqli' => true,
            'xss' => true,
            'traversal' => true,
            'command_injection' => true,
            'eval_based' => true,
            'php_code_execution' => true,
            'ssrf' => true,
            'ssrf_localhost' => false,
            'xxe' => true,
            'template_injection' => true,
            'crlf_injection' => true,
        ]);

        $clean = (static function (): string {
            $rows = [];
            for ($i = 0; $i < 200; $i++) {
                $rows[] = ['id' => $i, 'name' => 'customer_' . $i, 'note' => 'regular order #' . $i];
            }
            return json_encode(['records' => $rows]);
        })();

        $hit = app(PayloadInjectionRule::class)->inspect($clean);

        $this->assertFalse($hit['matched'], 'Clean JSON payload must not trigger WAF.');
    }

    public function test_decoder_bounds_never_drops_attack_vector(): void
    {
        $decoder = new PayloadDecoder();

        $inputs = [
            'query' => ['q' => "1' OR '1'='1"],
            'body' => ['comment' => '<script>alert(1)</script>'],
            'raw_content' => '{"nested":{"deep":"UNION SELECT * FROM users--"}}' . str_repeat('x', 5000),
            'path' => '/api/search',
        ];

        $decoded = $decoder->addDecodedTargets($inputs);

        // Original inputs preserved.
        $this->assertSame($inputs['query'], $decoded['query']);
        $this->assertSame($inputs['raw_content'], $decoded['raw_content']);

        // Decoded variants present for query/body/raw.
        $this->assertArrayHasKey('query_decoded', $decoded);
        $this->assertArrayHasKey('body_decoded', $decoded);
        $this->assertArrayHasKey('raw_decoded', $decoded);
        $this->assertArrayHasKey('raw_crlf_normalized', $decoded);

        // Raw attack content is still discoverable through raw variants.
        $this->assertStringContainsString('UNION SELECT', $decoded['raw_decoded']);
        $this->assertLessThanOrEqual(4096, strlen($decoded['raw_decoded']));
    }
}