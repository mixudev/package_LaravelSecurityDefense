<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\DTO;

use DateTimeInterface;
use Mixudev\SecurityDefense\Support\Sanitizer;

/**
 * Normalized and sanitized Security Event DTO.
 */
class SecurityEvent
{
    public readonly string $ip;
    public readonly string $identifier;
    public readonly string $eventType;
    public readonly string $timestamp;
    public readonly string $userAgent;
    /** @var array<string, mixed> */
    public readonly array $metadata;

    /**
     * @param string $ip
     * @param string $identifier
     * @param string $eventType
     * @param string|DateTimeInterface|null $timestamp
     * @param string $userAgent
     * @param array<string, mixed> $metadata
     */
    public function __construct(
        string $ip,
        string $identifier,
        string $eventType,
        string|DateTimeInterface|null $timestamp = null,
        string $userAgent = '',
        array $metadata = []
    ) {
        $this->ip = trim($ip) !== '' ? trim($ip) : '127.0.0.1';
        $this->identifier = trim($identifier) !== '' ? trim($identifier) : 'anonymous';
        $this->eventType = trim($eventType);
        
        if ($timestamp instanceof DateTimeInterface) {
            $this->timestamp = $timestamp->format(DateTimeInterface::ATOM);
        } elseif (is_string($timestamp) && trim($timestamp) !== '') {
            $this->timestamp = trim($timestamp);
        } else {
            $this->timestamp = gmdate(DateTimeInterface::ATOM);
        }

        $this->userAgent = trim($userAgent);
        $this->metadata = Sanitizer::clean($metadata);
    }

    /**
     * Create a SecurityEvent from a raw associative array.
     *
     * @param array<string, mixed> $data
     * @return self
     */
    public static function fromArray(array $data): self
    {
        return new self(
            ip: (string) ($data['ip'] ?? '127.0.0.1'),
            identifier: (string) ($data['identifier'] ?? 'anonymous'),
            eventType: (string) ($data['eventType'] ?? $data['event_type'] ?? 'GenericSecurityEvent'),
            timestamp: isset($data['timestamp']) ? (string) $data['timestamp'] : null,
            userAgent: (string) ($data['userAgent'] ?? $data['user_agent'] ?? ''),
            metadata: is_array($data['metadata'] ?? null) ? $data['metadata'] : []
        );
    }

    /**
     * Convert the DTO to an array representation.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'ip' => $this->ip,
            'identifier' => $this->identifier,
            'eventType' => $this->eventType,
            'timestamp' => $this->timestamp,
            'userAgent' => $this->userAgent,
            'metadata' => $this->metadata,
        ];
    }
}
