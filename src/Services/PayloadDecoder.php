<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Services;

use Illuminate\Support\Arr;

/**
 * Decodes obfuscated request values into multiple scan-target variants so the
 * payload scanner can match the semantic content even when attackers use
 * percent-encoding, double-encoding, CRLF, unicode escapes, or fullwidth forms.
 */
class PayloadDecoder
{
    /**
     * Add URL-decoded, CRLF-normalized, unicode-decoded, NFKC-normalized and
     * literal-escape-decoded copies of all string values in the given inputs.
     *
     * ponytail: per-field depth limit keeps cost linear; nested arrays use
     * Arr::flatten(); add recursive walker when input trees exceed 10K nodes.
     *
     * @param array<string, mixed> $inputs
     * @return array<string, mixed>
     */
    public function addDecodedTargets(array $inputs): array
    {
        $decoded = [];
        $rawContent = $inputs['raw_content'] ?? '';
        $maxLength = max(1, (int) config('security-defense.hardening.max_inspection_length', 4096));
        if (is_string($rawContent) && $rawContent !== '') {
            // Bound attacker-controlled bytes before decoding or regex work.
            $rawContent = strlen($rawContent) > $maxLength
                ? substr($rawContent, 0, $maxLength)
                : $rawContent;
            $decoded['raw_decoded'] = rawurldecode($rawContent);
            // form-urlencoded encodes a space as '+', and rawurldecode() leaves
            // '+' untouched. Without this variant a SQLi whose keywords are
            // separated by '+' keeps no literal whitespace and evades every
            // signature that requires \s+ between tokens.
            $decoded['raw_form_decoded'] = urldecode($rawContent);
            $decoded['raw_form_double_decoded'] = urldecode(urldecode($rawContent));
            // Normalize CRLF/CR/LF to spaces so CRLF injection shows as literal pattern
            $decoded['raw_crlf_normalized'] = str_replace(["\r\n", "\r", "\n"], ' ', $rawContent);
            // Unicode escape sequences (Burp Suite / JS obfuscation): \u0027 -> '
            $decoded['raw_unicode_decoded'] = preg_replace_callback(
                '/\\\\u([0-9a-fA-F]{4})/i',
                fn (array $match): string => $this->unicodeCodepoint((int) hexdec($match[1])),
                $rawContent
            );
        }

        foreach (['query', 'body'] as $source) {
            if (empty($inputs[$source]) || !is_array($inputs[$source])) {
                continue;
            }

            $flat = Arr::flatten($inputs[$source]);
            $parts = [];

            foreach ($flat as $value) {
                if (!is_string($value)) {
                    continue;
                }

                $parts[] = rawurldecode($value);
                // form-urlencoded '+' is a space; rawurldecode() keeps it literal,
                // so a '+'-separated payload never gains the \s+ its signature needs.
                $parts[] = urldecode($value);
                // Double-decode for %2527 -> %27 -> ' (Burp double-encoding)
                $parts[] = rawurldecode(rawurldecode($value));
                $parts[] = str_replace(["\r\n", "\r", "\n"], ' ', $value);
                // Unicode escape sequences: \u0027 -> ' (Burp/JS obfuscation)
                $parts[] = preg_replace_callback(
                    '/\\\\u([0-9a-fA-F]{4})/i',
                    fn (array $match): string => $this->unicodeCodepoint((int) hexdec($match[1])),
                    $value
                );
                // Fullwidth Unicode normalization: ＳＥＬＥＣＴ -> SELECT (NFKC) when intl available
                $normalizer = class_exists('\Normalizer') ? \Normalizer::normalize($value, \Normalizer::FORM_KC) : null;
                if ($normalizer !== false && $normalizer !== null && $normalizer !== $value) {
                    $parts[] = $normalizer;
                }
                // Literal escape-sequence decode: \s\s -> spaces, \t -> tab (sqlmap/etc.)
                $parts[] = str_replace(['\\s', '\\t', '\\n', '\\r'], [' ', "\t", "\n", "\r"], $value);
            }

            if (!empty($parts)) {
                $decoded[$source . '_decoded'] = implode(' ', $parts);
            }
        }

        return array_merge($inputs, $decoded);
    }

    private function unicodeCodepoint(int $codepoint): string
    {
        if ($codepoint < 0 || $codepoint > 0x10FFFF || ($codepoint >= 0xD800 && $codepoint <= 0xDFFF)) {
            return '';
        }

        if (function_exists('mb_chr')) {
            return mb_chr($codepoint, 'UTF-8');
        }

        if ($codepoint <= 0x7F) {
            return chr($codepoint);
        }
        if ($codepoint <= 0x7FF) {
            return chr(0xC0 | ($codepoint >> 6)) . chr(0x80 | ($codepoint & 0x3F));
        }
        if ($codepoint <= 0xFFFF) {
            return chr(0xE0 | ($codepoint >> 12))
                . chr(0x80 | (($codepoint >> 6) & 0x3F))
                . chr(0x80 | ($codepoint & 0x3F));
        }

        return chr(0xF0 | ($codepoint >> 18))
            . chr(0x80 | (($codepoint >> 12) & 0x3F))
            . chr(0x80 | (($codepoint >> 6) & 0x3F))
            . chr(0x80 | ($codepoint & 0x3F));
    }
}