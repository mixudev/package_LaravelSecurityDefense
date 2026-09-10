<?php
declare(strict_types=1);

namespace Mixudev\SecurityDefense\Epistemic\Evidence;

use DateTimeImmutable;
use Throwable;
use Mixudev\SecurityDefense\DTO\SecurityEvent;
use Mixudev\SecurityDefense\DTO\SecurityThreat;
use Mixudev\SecurityDefense\Epistemic\ValueObjects\Confidence;
use Mixudev\SecurityDefense\Epistemic\ValueObjects\EvidenceType;
use Mixudev\SecurityDefense\Support\Sanitizer;

/** Maps existing detection DTOs to epistemic Evidence. */
final class EvidenceBuilder
{
    private static array $EVENT_MAP = [
        'LoginFailed' => EvidenceType::LOGIN_FAILED,
        'OTP_FAILED' => EvidenceType::OTP_FAILED,
        'LoginSucceeded' => EvidenceType::LOGIN_SUCCESS,
        'NewDeviceLoginDetected' => EvidenceType::NEW_DEVICE,
        'PasswordReset' => EvidenceType::PASSWORD_RESET,
        'SessionAnomalyDetected' => EvidenceType::SESSION_ANOMALY,
        'ImpossibleTravel' => EvidenceType::IMPOSSIBLE_TRAVEL,
        'RateLimitTriggered' => EvidenceType::RATE_LIMIT_TRIGGERED,
    ];

    private static array $THREAT_MAP = [
        'brute_force' => EvidenceType::BRUTE_FORCE,
        'credential_stuffing' => EvidenceType::BRUTE_FORCE,
        'payload_injection' => EvidenceType::PAYLOAD_INJECTION,
        'impossible_travel' => EvidenceType::IMPOSSIBLE_TRAVEL,
        'session_fingerprint' => EvidenceType::SESSION_ANOMALY,
        'behavioral_velocity' => EvidenceType::BEHAVIOR_ANOMALY,
        'compound_threat' => EvidenceType::COMPOUND_THREAT,
    ];

    public static function fromSecurityEvent(SecurityEvent $event, int $allowedClockSkewSeconds = 60, ?DateTimeImmutable $now = null): ?Evidence
    {
        $type = self::$EVENT_MAP[$event->eventType] ?? null;
        $occurredAt = self::safeTimestamp($event->timestamp, $allowedClockSkewSeconds, $now);
        return $type === null || $occurredAt === null ? null : new Evidence(
            type: $type, source: 'security_event', occurredAt: $occurredAt,
            reliability: Confidence::from(0.8), metadata: Sanitizer::clean($event->metadata),
            id: self::metadataId($event->metadata),
        );
    }

    public static function fromSecurityThreat(SecurityThreat $threat, int $allowedClockSkewSeconds = 60, ?DateTimeImmutable $now = null): ?Evidence
    {
        $type = self::$THREAT_MAP[$threat->threatType] ?? null;
        $occurredAt = self::safeTimestamp($threat->detectedAt, $allowedClockSkewSeconds, $now);
        return $type === null || $occurredAt === null ? null : new Evidence(
            type: $type, source: $threat->ruleIdentifier ?: 'rule_engine', occurredAt: $occurredAt,
            reliability: Confidence::from(0.85), metadata: Sanitizer::clean($threat->metadata),
            id: self::metadataId($threat->metadata),
        );
    }

    private static function safeTimestamp(string $value, int $allowedClockSkewSeconds, ?DateTimeImmutable $now): ?DateTimeImmutable
    {
        try {
            $parsed = new DateTimeImmutable($value);
        } catch (Throwable) {
            return null;
        }
        $now ??= new DateTimeImmutable();
        return $parsed->getTimestamp() <= $now->getTimestamp() + max(0, $allowedClockSkewSeconds) ? $parsed : null;
    }

    private static function metadataId(array $metadata): ?string
    {
        $id = $metadata['id'] ?? $metadata['event_id'] ?? null;
        return is_string($id) && $id !== '' ? $id : null;
    }
}
