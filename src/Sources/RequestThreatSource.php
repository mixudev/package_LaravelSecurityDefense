<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Sources;

use Illuminate\Http\Request;
use Mixudev\SecurityDefense\Contracts\ThreatSource;
use Mixudev\SecurityDefense\DTO\SecurityEvent;
use Mixudev\SecurityDefense\Support\Sanitizer;

/**
 * Adapter converting an Illuminate\Http\Request into a SecurityEvent.
 */
class RequestThreatSource implements ThreatSource
{
    /**
     * @param Request $request
     * @param string $eventType
     * @param string|null $identifier
     * @param array<string, mixed> $extraMetadata
     */
    public function __construct(
        protected Request $request,
        protected string $eventType = 'HttpRequestTelemetry',
        protected ?string $identifier = null,
        protected array $extraMetadata = []
    ) {
    }

    /**
     * Convert HTTP request into normalized SecurityEvent.
     */
    public function toSecurityEvent(): SecurityEvent
    {
        $identifier = (string) ($this->identifier
            ?: $this->request->user()?->getAuthIdentifier()
            ?: ($this->request->input('email') !== null ? hash('sha256', strtolower((string) $this->request->input('email'))) : null)
            ?: ($this->request->input('username') !== null ? hash('sha256', strtolower((string) $this->request->input('username'))) : null)
            ?: 'guest');
        $identifier = Sanitizer::cleanString($identifier);

        // Keep forensic shape, but never carry raw proxy data, query secrets, or untrusted extras.
        $headers = array_filter([
            'x_forwarded_for_hash' => $this->request->header('x-forwarded-for') ? hash('sha256', (string) $this->request->header('x-forwarded-for')) : null,
            'cf_connecting_ip_hash' => $this->request->header('cf-connecting-ip') ? hash('sha256', (string) $this->request->header('cf-connecting-ip')) : null,
        ]);
        $metadata = Sanitizer::clean(array_merge([
            'method' => $this->request->method(),
            'url' => $this->request->url(),
            'path' => $this->request->path(),
            'route' => $this->request->route()?->getName(),
            'headers' => $headers,
            'query' => $this->request->query(),
        ], $this->extraMetadata));
        $metadata = array_slice($metadata, 0, 32, true);

        return new SecurityEvent(
            ip: (string) ($this->request->ip() ?: '127.0.0.1'),
            identifier: (string) $identifier,
            eventType: $this->eventType,
            timestamp: now()->toIso8601String(),
            userAgent: (string) ($this->request->userAgent() ?: ''),
            metadata: $metadata
        );
    }
}
