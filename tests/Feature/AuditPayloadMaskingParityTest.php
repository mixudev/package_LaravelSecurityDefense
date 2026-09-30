<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature;

use Mixudev\SecurityDefense\Services\AuditPayloadSanitizer;
use Mixudev\SecurityDefense\Support\Sanitizer;
use Mixudev\SecurityDefense\Tests\TestCase;

/**
 * Regression: AuditPayloadSanitizer::resolveMaskedColumns() only listed 8
 * default patterns, while Support\Sanitizer::$sensitiveKeys defined 22
 * patterns (including api_key, private_key, otp, access_token, etc.).
 *
 * When an Eloquent model mutated a column like `api_key`, `private_key`, or
 * `otp_code`, the mutation was persisted to security_data_audits in PLAINTEXT
 * because resolveMaskedColumns() fell back to its narrow 8-item default.
 *
 * The two lists should be merged so the audit table never persists secrets
 * that the sanitizer already recognizes as sensitive.
 */
final class AuditPayloadMaskingParityTest extends TestCase
{
    public function test_masked_columns_include_all_sanitizer_sensitive_keys(): void
    {
        $sanitizer = new AuditPayloadSanitizer();

        $model = new class extends \Illuminate\Database\Eloquent\Model {
            protected $table = 'users';
        };

        $masked = $sanitizer->resolveMaskedColumns($model);

        // Every pattern that Sanitizer considers sensitive must be masked
        // in audit rows, otherwise an Eloquent mutation stores in plaintext
        // secrets that the rest of the package redacts.
        $criticalKeys = [
            'api_key',
            'access_token',
            'refresh_token',
            'private_key',
            'otp',
            'totp',
            'pin',
            'card_number',
            'cvv',
            'cvc',
            'bot_token',
            'webhook_url',
        ];

        $missing = [];
        foreach ($criticalKeys as $key) {
            $isMasked = in_array($key, $masked, true) || Sanitizer::isSensitiveKey($key, $masked);
            if (! $isMasked) {
                $missing[] = $key;
            }
        }

        self::assertSame(
            [],
            $missing,
            'Audit table does not mask columns that the package recognizes as sensitive: '
            . implode(', ', $missing) . '. A mutation on these columns persists plaintext '
            . 'credentials to security_data_audits.'
        );
    }
}
