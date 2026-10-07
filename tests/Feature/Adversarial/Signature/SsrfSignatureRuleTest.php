<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature\Adversarial\Signature;

use PHPUnit\Framework\Attributes\DataProvider;
use Mixudev\SecurityDefense\Tests\TestCase;

/**
 * SSRF signature: default posture, then behaviour once enabled.
 *
 * Why SSRF is a fail-closed candidate (documented reason, package default):
 * the signature matches ANY private-range literal (10.x, 192.168.x, 172.16-31.x)
 * plus 0.0.0.0 and any gopher/dict/file URL. Real applications legitimately
 * send those values: webhook callbacks to an internal service, health checks,
 * admin tools pasting a LAN host, photo uploads pointing at 10.0.0.5. A
 * blanket signature therefore blocks ordinary traffic on any app with an
 * internal integration, which is why only the localhost/127.0.0.1 variant is
 * shipped disabled-by-default and the rest are documented as opt-in hardening.
 */
class SsrfSignatureRuleTest extends TestCase
{
    use ConfiguresSignatureRules;

    protected function setUp(): void
    {
        parent::setUp();
        $this->setUpSignatureProbe();
    }

    /**
     * Documented default: SSRF signatures ship disabled.
     *
     * False-positive reason: the signature matches ANY private-range literal
     * (10.x/192.168.x/172.16-31.x), 0.0.0.0, and localhost/127.0.0.1. Real
     * apps legitimately send those: webhook callbacks to internal services,
     * health checks, admin tools pasting a LAN host, dev servers posting
     * telemetry to their own origin. On any host with an internal integration
     * the signature blocks ordinary traffic, so operators must opt in.
     */
    public function test_default_config_disables_ssrf_signatures(): void
    {
        $patterns = (array) config('security-defense.detection.rules.payload_injection.patterns');

        $this->assertArrayHasKey('ssrf', $patterns, 'SSRF pattern key missing from package defaults.');
        $this->assertFalse((bool) ($patterns['ssrf'] ?? true), 'Private-range SSRF must ship disabled.');
        $this->assertFalse(
            (bool) ($patterns['ssrf_localhost'] ?? true),
            'Loopback SSRF must ship disabled: same-origin dev/telemetry traffic would be blocked.'
        );
    }

    /**
     * A host app that never publishes/overrides the package config receives these
     * defaults via mergeConfigFrom. Prove the effective runtime value, not just
     * the file, so a provider-level override cannot silently re-enable the rule.
     */
    public function test_effective_runtime_default_matches_package_defaults(): void
    {
        $this->assertFalse(
            (bool) config('security-defense.detection.rules.payload_injection.patterns.ssrf'),
            'Runtime default drifted from the package config file.'
        );
        $this->assertFalse(
            (bool) config('security-defense.detection.rules.payload_injection.patterns.ssrf_localhost')
        );
    }

    #[DataProvider('ssrfTruePositiveProvider')]
    public function test_ssrf_payload_is_blocked_when_signature_enabled(string $payload): void
    {
        $this->assertBlocked($payload, 'ssrf', 1);
    }

    #[DataProvider('loopbackProvider')]
    public function test_loopback_ssrf_is_blocked_when_loopback_signature_enabled(string $payload): void
    {
        $this->assertBlocked($payload, 'ssrf_localhost', 2);
    }

    /** @return array<string, array{0: string}> */
    public static function loopbackProvider(): array
    {
        return [
            'localhost loopback' => ['http://localhost:8000/_ignition/execute-solution'],
            '127.0.0.1 loopback' => ['http://127.0.0.1:6379/'],
            'localhost with path' => ['https://localhost/adminer.php'],
            'localhost no scheme' => ['localhost:8080/admin'],
        ];
    }

    /**
     * These targets are intentionally separate from the loopback corpus: the
     * package has two signatures with different opt-in reasons.
     */
    public function test_localhost_payload_is_allowed_by_private_range_signature(): void
    {
        $this->enableSignature('ssrf');
        $result = $this->probeForm('url', 'http://localhost:8000/health', '198.18.9.7');
        $this->assertSame(200, $result['status']);
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function ssrfTruePositiveProvider(): array
    {
        return [
            'cloud metadata' => ['http://169.254.169.254/latest/meta-data/'],
            'cloud metadata imds v2 path' => ['http://169.254.169.254/latest/meta-data/iam/security-credentials/'],
            'cloud metadata no scheme' => ['169.254.169.254/latest/meta-data/'],
            'zero address' => ['http://0.0.0.0:80/admin'],
            'private 10 range' => ['http://10.0.0.5/internal-api'],
            'private 192.168 range' => ['http://192.168.1.1/router-config'],
            'private 172.16 range' => ['http://172.16.0.9/secrets'],
            'private 172.31 range' => ['http://172.31.255.255/'],
            'gopher scheme' => ['gopher://127.0.0.1:6379/_INFO'],
            'dict scheme' => ['dict://10.0.0.1:2628/HELP'],
            'file scheme passwd' => ['file:///etc/passwd'],
            'file scheme win ini' => ['file:///C:/windows/win.ini'],
            'ftp scheme internal' => ['ftp://192.168.0.10/pub/'],
            'ldap scheme' => ['ldap://10.1.2.3:389/dc=local'],
            'tftp scheme' => ['tftp://172.16.0.1/boot.cfg'],
            'scgi scheme' => ['scgi://10.0.0.9:4000/'],
        ];
    }

    public function test_ssrf_true_positive_is_reported_as_ssrf_category(): void
    {
        $this->enableSignature('ssrf');
        $result = $this->probeForm('url', 'http://169.254.169.254/latest/meta-data/', '198.18.9.1');

        $this->assertSame(403, $result['status']);
        $this->assertStringContainsString('Suspicious request payload', $result['body']);
    }

    public function test_log_only_action_still_records_but_does_not_block(): void
    {
        $this->enableSignature('ssrf');
        config()->set('security-defense.middleware.payload_scanner.action', 'log_only');

        $result = $this->probeForm('url', 'http://169.254.169.254/latest/meta-data/', '198.18.9.2');

        $this->assertSame(200, $result['status'], 'log_only must not block');
    }

    public function test_json_body_ssrf_is_blocked(): void
    {
        $this->enableSignature('ssrf');
        $result = $this->probeJson('target', 'http://169.254.169.254/latest/meta-data/', '198.18.9.3');

        $this->assertSame(403, $result['status'], 'JSON body SSRF bypassed the scanner');
    }

    public function test_query_string_ssrf_is_blocked(): void
    {
        $this->enableSignature('ssrf');
        $result = $this->probeGet('http://169.254.169.254/latest/meta-data/', '198.18.9.4');

        $this->assertSame(403, $result['status'], 'Query SSRF bypassed the scanner');
    }

    public function test_url_encoded_ssrf_is_blocked(): void
    {
        $this->enableSignature('ssrf');
        // %3A%2F%2F is "://" ; the decoder pipeline must expose it.
        $result = $this->probeForm('url', 'http%3A%2F%2F169.254.169.254%2Flatest', '198.18.9.5');

        $this->assertSame(403, $result['status'], 'Single-encoded SSRF bypassed the scanner');
    }

    public function test_disabled_signature_lets_ssrf_payload_pass(): void
    {
        // Proves the signature is the ONLY reason the payload is blocked.
        config()->set('security-defense.detection.rules.payload_injection.patterns.ssrf', false);
        config()->set('security-defense.detection.rules.payload_injection.patterns.ssrf_localhost', false);

        $result = $this->probeForm('url', 'http://169.254.169.254/latest/meta-data/', '198.18.9.6');

        $this->assertSame(
            200,
            $result['status'],
            'Expected the payload to pass while the signature is disabled'
        );
    }
}
