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
        'sqli' => '/(\b(union(\s+all)?\s+select|select\s+[\s\S]*?\s+from|insert\s+into|update\s+[\s\S]*?\s+set|delete\s+from|drop\s+(table|database)|truncate\s+table)\b|(\'|\")\s*(\b(or|and)\b)\s*(\'|\")?[^\s\']+?(\'|\")?\s*=\s*(\'|\")?[^\s\']+?|(\'|\")\s*--|(\bwaitfor\s+delay\b|\bsleep\(\d+\)|\bbenchmark\(\d+,))/is',
        'xss' => '/(<script\b[^>]*>[\s\S]*?<\/script>|<script\b[^>]*>|<\/script>|javascript\s*:|on(error|load|click|mouseover|submit|focus)\s*=|document\.(cookie|location)|<[a-z0-9]+\b[^>]*?(onerror|onload|onclick)\s*=|alert\(|prompt\(|confirm\()/is',
        'traversal' => '/(\.\.[\/\\\\]|\.\.%2f|\.\.%5c|\b(etc[\/\\\\]passwd|windows[\/\\\\]win\.ini|boot\.ini)\b)/is',
        'command_injection' => '/(;|\&|\||\`|\$\()\s*(cat\s+[\/.]|ls\s+-|whoami|id|uname\s+-|netstat|curl\s+https?|wget\s+https?|cmd\.exe|powershell)\b/is',
        'eval_based' => '/(\beval\s*\(|\bbase64_decode\s*\(|\bpassthru\s*\(|\bshell_exec\s*\(|\bsystem\s*\()/is',
        'template_injection' => '/(\{\{\s*[\s\S]*?\b(system|exec|passthru|shell_exec|phpinfo)\b[\s\S]*?\}\}|\$\{\s*[\s\S]*?\b(env|cmd|exec)\b[\s\S]*?\})/is',
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

            // Anti-ReDoS truncation
            $safeContent = strlen($content) > $maxLength ? substr($content, 0, $maxLength) : $content;

            foreach ($this->signatures as $category => $pattern) {
                if (empty($activeCategories[$category])) {
                    continue;
                }

                if (preg_match($pattern, $safeContent, $matches)) {
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
                            'target_identifier' => $event->identifier,
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

            // Anti-ReDoS truncation
            $safeValue = strlen($value) > $maxLength ? substr($value, 0, $maxLength) : $value;

            foreach ($this->signatures as $category => $pattern) {
                if (empty($activeCategories[$category])) {
                    continue;
                }

                if (preg_match($pattern, $safeValue, $matches)) {
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

        if (isset($event->metadata['path']) && is_string($event->metadata['path'])) {
            $payloads['path'] = $event->metadata['path'];
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
