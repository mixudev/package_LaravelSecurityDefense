<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\DTO;

use DateTimeInterface;
use Mixudev\SecurityDefense\Support\Sanitizer;

/**
 * Represents a security threat identified by one or more detection rules.
 */
class SecurityThreat
{
    public readonly string $severity;
    public readonly string $threatType;
    public readonly string $fingerprint;
    /** @var array<string, mixed> */
    public readonly array $metadata;
    public readonly string $ruleIdentifier;
    public readonly string $detectedAt;

    /**
     * @param string $severity (low, medium, high, critical)
     * @param string $threatType
     * @param string $fingerprint
     * @param array<string, mixed> $metadata
     * @param string $ruleIdentifier
     * @param string|DateTimeInterface|null $detectedAt
     */
    public function __construct(
        string $severity,
        string $threatType,
        string $fingerprint,
        array $metadata = [],
        string $ruleIdentifier = '',
        string|DateTimeInterface|null $detectedAt = null
    ) {
        $validSeverities = ['low', 'medium', 'high', 'critical'];
        $normalizedSeverity = strtolower(trim($severity));
        $this->severity = in_array($normalizedSeverity, $validSeverities, true) ? $normalizedSeverity : 'medium';

        $this->threatType = trim($threatType);
        $this->ruleIdentifier = trim($ruleIdentifier);
        $this->metadata = Sanitizer::clean($metadata);

        if ($detectedAt instanceof DateTimeInterface) {
            $this->detectedAt = $detectedAt->format(DateTimeInterface::ATOM);
        } elseif (is_string($detectedAt) && trim($detectedAt) !== '') {
            $this->detectedAt = trim($detectedAt);
        } else {
            $this->detectedAt = gmdate(DateTimeInterface::ATOM);
        }

        $this->fingerprint = trim($fingerprint) !== ''
            ? trim($fingerprint)
            : static::generateFingerprint($this->threatType, $this->metadata);
    }

    /**
     * Generate a deterministic fingerprint based on threat type and key attributes.
     *
     * @param string $threatType
     * @param array<string, mixed> $metadata
     * @return string
     */
    public static function generateFingerprint(string $threatType, array $metadata): string
    {
        $target = (string) ($metadata['target'] ?? $metadata['identifier'] ?? $metadata['ip'] ?? '');
        $signature = (string) ($metadata['signature'] ?? $metadata['rule'] ?? '');

        return hash('sha256', sprintf('%s:%s:%s', strtolower($threatType), strtolower($target), strtolower($signature)));
    }

    /**
     * Convert threat to associative array.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'severity' => $this->severity,
            'threatType' => $this->threatType,
            'fingerprint' => $this->fingerprint,
            'ruleIdentifier' => $this->ruleIdentifier,
            'metadata' => $this->metadata,
            'detectedAt' => $this->detectedAt,
        ];
    }
}
