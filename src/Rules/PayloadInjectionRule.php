<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Rules;

use Mixudev\SecurityDefense\DTO\SecurityEvent;
use Mixudev\SecurityDefense\DTO\SecurityThreat;

/**
 * Detects common web payload injections (SQLi, XSS, Path Traversal, OS Command Injection).
 * Hardened with string bounds to prevent Regular Expression Denial of Service (ReDoS).
 */
class PayloadInjectionRule extends AbstractDetectionRule
{
    public function identifier(): string
    {
        return 'payload_injection';
    }

    public function name(): string
    {
        return 'Payload Injection Detector (WAF)';
    }

    /**
     * Common attack signatures.
     *
     * @var array<string, string>
     */
    protected array $signatures = [
        'sqli' => '/(\b(union(\s+all)?\s+select|union\s*\/\*[\s\S]{0,100}?\*\/\s*select|select\s+[\s\S]{0,500}?\s+from\s+[\w.]+\s*(where\b|order\s+by\b|limit\b|group\s+by\b|having\b|--|;|\(|>|<|$)|insert\s+into\s+[\w.]+\s*\(|insert\s+into\s+[\w.]+\s+values\b|update\s+[\w.]+(?:\s*,\s*[\w.]+)*\s+set\s+[\w.]+\s*=|delete\s+from\s+[\w.]+\s*(where\b|--|;|\(|$)|drop\s+(table|database)\b|truncate\s+table\b)|(\'|\")\s*(\b(or|and)\b)\s*(\'|\")?[^\s\']+?(\'|\")?\s*=\s*(\'|\")?[^\s\']+?|(\')\s*\)?\s*(\bor\b|\band\b|\bxor\b)\s*\(?\s*(\'|\")?\d+(\'|\")?\s*=\s*(\'|\")?\d+|(\')\s*(\bor\b|\band\b)\s*\(\s*select\b[\s\S]{0,500}?\bfrom\b[\s\S]{0,100}?(--|;|>|<)|(\')\s*#|(\')\s*(\bor\b|\band\b|\bxor\b)\s+\d+\s+not\s+between\b|(\bor\b|\band\b|\bxor\b)\s+case\s+when\b|(\')\s*(\bor\b|\band\b)\s+\w+\s+(not\s+)?like\b|\border\s+by\s+\d+\b|(\'|\")\s*--|(\bwaitfor\s+delay\b|\bsleep\s*\(\s*\d+(?:\.\d+)?\s*\)|\bbenchmark\s*\(\s*\d+\s*,)|(\bor\b|\band\b|\bunion\b|\bxor\b)\s+\d+\s*=\s*\d+)/is',
        'xss' => '/(<script\b[^>]*>[\s\S]*?<\/script>|<script\b[^>]*>|<\/script>|javascript\s*:|vbscript\s*:|data\s*:\s*text\/html|on(error|load|click|mouseover|submit|focus)\s*=|document\.(cookie|location)|window\.location(?:\.href)?\s*=|<[a-z0-9]+\b[^>]*?(onerror|onload|onclick)\s*=|<math\b|<maction\b|xlink:href\s*=|alert\(|prompt\(|confirm\()/is',
        'traversal' => '/(\.\.[\/\\\\]|\.\.%2f|\.\.%5c|%00|\b(etc[\/\\\\]passwd|windows[\/\\\\]win\.ini|boot\.ini)\b)/is',
        'command_injection' => '/(;|\&|\||\`|\$\()\s*(cat\s+[\/.]|ls\s+-|whoami|id|uname\s+-|netstat|curl\s+https?|wget\s+https?|cmd\.exe|powershell|bash\s+-c|nc\s+-e|ping\s+-c|(?:(?:\/)?bin\/)?bash\s+-c)\b|(^|[;|&])\s*(phpinfo|shell_exec|system|exec)\(/is',
        'eval_based' => '/(\beval\s*\(|\bbase64_decode\s*\(|\bpassthru\s*\(|\bshell_exec\s*\(|\bsystem\s*\(|\bphpinfo\s*\()/is',
        'php_code_execution' => '/(\b(include|require|include_once|require_once)\s*\(?\s*[\'"](?:https?:|php:|data:|file:)|<\?php\b|\b(assert|create_function|call_user_func|preg_replace)\s*\(\s*[\'"][\/]?.*(e|eval)|(?:@)?\s*\$\_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\b)/is',
        'ssrf' => '/(\b(gopher|dict|file|ftp|ldap|tftp|scgi)\s*:\/\/|(?:https?:\/\/)?(?:169\.254\.169\.254|0\.0\.0\.0|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?::\d{1,5})?[\/\s"\'])/is',
                // localhost/127.0.0.1 SSRF is OFF by default: apps legitimately reference
                // their own origin (e.g. browser telemetry posting http://localhost:8000/).
                // Opt back in via detection.rules.payload_injection.patterns.ssrf_localhost
                // on hardened/strict deployments where local-only pivot targets matter.
                'ssrf_localhost' => '/(?:https?:\/\/)?(?:127\.0\.0\.1|localhost)(?::\d{1,5})?[\/\s"\']/is',
        'xxe' => '/(<!DOCTYPE\s+[a-z0-9_-]+|<!ENTITY\s+%?\s*[a-z0-9_-]+\s+(SYSTEM|PUBLIC)|xsi:noNamespaceSchemaLocation|xmlns:xsi)/is',
        'template_injection' => '/(\{\{\s*[\s\S]*?\b(system|exec|passthru|shell_exec|phpinfo)\b[\s\S]*?\}\}|\$\{\s*[\s\S]*?\b(env|cmd|exec)\b[\s\S]*?\})/is',
        'crlf_injection' => '/(\r\n|\r|\n)\s*([a-z0-9-]+:\s*.*|Set-Cookie:|Location:|X-)/is',
    ];

    public function evaluate(SecurityEvent $event): ?SecurityThreat
    {
        if (!$this->isEnabled()) {
            return null;
        }

        $activeCategories = (array) $this->getConfig('patterns', [
            'sqli' => true,
            'xss' => true,
            'traversal' => true,
            'command_injection' => true,
        ]);

        $payloadsToScan = $this->extractPayloads($event);
        $maxLength = (int) config('security-defense.hardening.max_inspection_length', 4096);

        foreach ($payloadsToScan as $field => $content) {
            if (!is_string($content) || trim($content) === '') {
                continue;
            }

            // Bound regex work while inspecting both edges. Scanning only the
            // prefix lets an attacker hide a payload behind harmless padding.
            $safeContents = strlen($content) > $maxLength
                ? [substr($content, 0, $maxLength), substr($content, -$maxLength)]
                : [$content];

            foreach ($this->signatures as $category => $pattern) {
                if (empty($activeCategories[$category])) {
                    continue;
                }

                foreach ($safeContents as $safeContent) {
                    if (! preg_match($pattern, $safeContent, $matches)) {
                        continue;
                    }

                    // Strip control characters to prevent log/markdown injection
                    $matchedSample = preg_replace('/[\x00-\x1f\x7f]/', '', substr($matches[0], 0, 50));
                    $fingerprint = hash('sha256', sprintf('payload_injection:%s:%s:%s', $category, $event->ip, $matchedSample));

                    return new SecurityThreat(
                        severity: (string) $this->getConfig('severity', 'critical'),
                        threatType: 'payload_injection',
                        fingerprint: $fingerprint,
                        metadata: [
                            'category' => $category,
                            'matched_field' => $field,
                            'matched_signature' => $matchedSample,
                            'ip' => $event->ip,
                            // Hash the target: metadata is broadcast to
                            // external channels, so a raw email or username
                            // is a disclosure of a valid account.
                            'target_hash' => hash('sha256', (string) $event->identifier),
                            'user_agent' => $event->userAgent,
                            'path' => $event->metadata['path'] ?? null,
                            'method' => $event->metadata['method'] ?? null,
                        ],
                        ruleIdentifier: $this->identifier()
                    );
                }
            }
        }

        return null;
    }

    /**
     * Inspect any arbitrary string or array directly (used by middleware).
     *
     * @param array<string, mixed>|string $input
     * @return array{matched: bool, category: string|null, sample: string|null, field: string|null}
     */
    public function inspect(array|string $input): array
    {
        $flattened = is_array($input) ? $this->flattenArray($input) : ['raw' => $input];
        $maxLength = (int) config('security-defense.hardening.max_inspection_length', 4096);

        $activeCategories = (array) $this->getConfig('patterns', [
            'sqli' => true,
            'xss' => true,
            'traversal' => true,
            'command_injection' => true,
            'eval_based' => true,
            'php_code_execution' => true,
            'template_injection' => true,
        ]);

        foreach ($flattened as $field => $value) {
            if (!is_string($value) || trim($value) === '') {
                continue;
            }

            // Bound regex work while inspecting both edges, so padding cannot
            // push a payload outside the inspection window.
            $safeValues = strlen($value) > $maxLength
                ? [substr($value, 0, $maxLength), substr($value, -$maxLength)]
                : [$value];

            foreach ($this->signatures as $category => $pattern) {
                if (empty($activeCategories[$category])) {
                    continue;
                }

                foreach ($safeValues as $safeValue) {
                    if (! preg_match($pattern, $safeValue, $matches)) {
                        continue;
                    }

                    // Strip control characters to prevent log/markdown injection
                    return [
                        'matched' => true,
                        'category' => $category,
                        'sample' => preg_replace('/[\x00-\x1f\x7f]/', '', substr($matches[0], 0, 50)),
                        'field' => $field,
                    ];
                }
            }
        }

        return [
            'matched' => false,
            'category' => null,
            'sample' => null,
            'field' => null,
        ];
    }

    /**
     * Extract string payloads from SecurityEvent metadata.
     *
     * @param SecurityEvent $event
     * @return array<string, string>
     */
    protected function extractPayloads(SecurityEvent $event): array
    {
        $payloads = [];

        if (isset($event->metadata['query']) && is_array($event->metadata['query'])) {
            $payloads = array_merge($payloads, $this->flattenArray($event->metadata['query'], 'query.'));
        }

        if (isset($event->metadata['input']) && is_array($event->metadata['input'])) {
            $payloads = array_merge($payloads, $this->flattenArray($event->metadata['input'], 'input.'));
        }

        if (isset($event->metadata['raw_payload']) && is_string($event->metadata['raw_payload'])) {
            $payloads['raw_payload'] = $event->metadata['raw_payload'];
        }

        if (isset($event->metadata['raw_content']) && is_string($event->metadata['raw_content'])) {
            $payloads['raw_content'] = $event->metadata['raw_content'];
        }

        if (isset($event->metadata['path']) && is_string($event->metadata['path'])) {
            $payloads['path'] = $event->metadata['path'];
        }

        // PayloadDecoder adds normalized/decoded copies under explicit keys.
        // Include those copies in the rule input; otherwise decoding is dead
        // code and form-urlencoded '+' separators remain an evasion path.
        foreach ($event->metadata as $key => $value) {
            if (!is_string($value) || !preg_match('/(?:_decoded|_form_decoded|_normalized)$/', (string) $key)) {
                continue;
            }

            $payloads[(string) $key] = $value;
        }

        return $payloads;
    }

    /**
     * Recursively flatten array into dot-notated string values.
     *
     * @param array<string, mixed> $array
     * @param string $prefix
     * @param int $depth
     * @return array<string, string>
     */
    protected function flattenArray(array $array, string $prefix = '', int $depth = 0): array
    {
        $maxDepth = (int) config('security-defense.hardening.max_traversal_depth', 10);
        if ($depth >= $maxDepth) {
            return [];
        }

        $result = [];

        foreach ($array as $key => $value) {
            $fullKey = $prefix . (string) $key;
            if (is_array($value)) {
                $result = array_merge($result, $this->flattenArray($value, $fullKey . '.', $depth + 1));
            } elseif (is_scalar($value)) {
                $result[$fullKey] = (string) $value;
            }
        }

        return $result;
    }
}
