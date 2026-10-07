<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature\Adversarial\Signature;

use PHPUnit\Framework\Attributes\DataProvider;
use Mixudev\SecurityDefense\Tests\TestCase;

/**
 * CRLF is disabled by default because raw line breaks are valid in ordinary
 * multiline form fields, pasted HTTP examples, PEM/certificate text, and
 * imported log records. A signature sees bytes, not whether the value later
 * reaches a response header, so enabling it is a deliberate host-policy
 * choice. The opt-in tests require a header-like continuation to distinguish
 * response splitting from harmless prose newlines.
 */
class CrlfSignatureRuleTest extends TestCase
{
    use ConfiguresSignatureRules;

    protected function setUp(): void
    {
        parent::setUp();
        $this->setUpSignatureProbe();
    }

    public function test_crlf_is_disabled_by_default(): void
    {
        $this->assertFalse((bool) config('security-defense.detection.rules.payload_injection.patterns.crlf_injection'));
    }

    #[DataProvider('crlfProvider')]
    public function test_crlf_response_splitting_payload_is_blocked_when_enabled(string $payload): void
    {
        $this->assertBlocked($payload, 'crlf_injection', 20);
    }

    #[DataProvider('crlfProvider')]
    public function test_crlf_payload_is_blocked_in_json_when_enabled(string $payload): void
    {
        $this->enableSignature('crlf_injection');
        $result = $this->probeJson('header', $payload, '198.18.20.2');
        $this->assertSame(403, $result['status'], "CRLF JSON bypassed: {$payload}");
    }

    /** @return array<string, array{0: string}> */
    public static function crlfProvider(): array
    {
        return [
            'raw set cookie CRLF' => ["ok\r\nSet-Cookie: admin=true"],
            'raw location CRLF' => ["/safe\r\nLocation: https://evil.test"],
            'raw x header CRLF' => ["value\r\nX-Injected: yes"],
            'raw arbitrary header CRLF' => ["value\r\nContent-Type: text/html"],
            'raw LF set cookie' => ["ok\nSet-Cookie: admin=true"],
            'raw CR location' => ["ok\rLocation: https://evil.test"],
            'encoded CRLF' => ['ok%0d%0aSet-Cookie:%20admin=true'],
            'encoded LF' => ['ok%0aX-Injected:%20yes'],
            'double encoded CRLF' => ['ok%250d%250aSet-Cookie:%20admin=true'],
            'lowercase cookie header' => ["ok\r\nset-cookie: session=attacker"],
            'content length split' => ["ok\r\nContent-Length: 0"],
            'cache control split' => ["ok\r\nCache-Control: public"],
            'forwarded host split' => ["ok\r\nHost: evil.test"],
            'origin split' => ["ok\r\nOrigin: https://evil.test"],
            'tab after newline' => ["ok\r\n\tSet-Cookie: role=admin"],
            'multiple headers' => ["ok\r\nX-One: 1\r\nX-Two: 2"],
            'url encoded location' => ['/safe%0d%0aLocation:%20https://evil.test'],
            'url encoded x header' => ['ok%0D%0AX-Original-URL:%20/admin'],
            'mixed line ending' => ["ok\r\nLocation: /admin\nSet-Cookie: a=b"],
            'header with hyphen' => ["ok\nX-Forwarded-Host: evil.test"],
        ];
    }

    public function test_benign_multiline_prose_with_no_header_line_is_not_blocked(): void
    {
        $this->enableSignature('crlf_injection');
        foreach ([
            "first line\nsecond line",
            "Support ticket\r\nThanks for investigating",
            "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
            "line one\rline two",
            'normal text with %0d%0a written literally',
            "Subject: quarterly report\r\nPlease review the attached numbers",
            "Dear team,\nthe release is scheduled for Friday",
        ] as $text) {
            $result = $this->probeForm('message', $text, '198.18.20.3');
            $this->assertSame(200, $result['status'], "Benign multiline false positive: {$text}");
        }
    }

    /**
     * UNDERSTOOD false positive, and the precise reason crlf_injection ships
     * disabled: a raw HTTP message pasted into a form field is byte-identical
     * to a response-splitting payload. Lexically there is no signal that
     * separates "user pasted a health-check transcript" from "attacker
     * injected Host:", so enabling the signature deliberately opts the host
     * into blocking raw HTTP text. Asserting BOTH states keeps the trade-off
     * visible instead of quietly deleting the corpus entry.
     */
    public function test_pasted_http_request_is_an_understood_false_positive(): void
    {
        $payload = "GET /health HTTP/1.1\nHost: example.test";

        // Default config: passes, because the signature ships disabled.
        $result = $this->probeForm('message', $payload, '198.18.20.5');
        $this->assertSame(200, $result['status'], 'Default config must not block raw HTTP text.');

        // Opted in: blocked by design; bytes cannot be told apart from splitting.
        $this->enableSignature('crlf_injection');
        $result = $this->probeForm('message', $payload, '198.18.20.6');
        $this->assertSame(403, $result['status'], 'Expected the understood false positive once enabled.');
    }

    public function test_disabled_crlf_payload_passes_for_default_compatibility(): void
    {
        $result = $this->probeForm('header', "safe\r\nSet-Cookie: attacker=true", '198.18.20.4');
        $this->assertSame(200, $result['status']);
    }
}
