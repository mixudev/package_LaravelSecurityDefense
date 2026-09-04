<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Sources;

use Illuminate\Http\Request;
use Mixudev\SecurityDefense\Contracts\ThreatSource;
use Mixudev\SecurityDefense\DTO\SecurityEvent;

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
        $identifier = $this->identifier
            ?: $this->request->user()?->getAuthIdentifier()
            ?: $this->request->input('email')
            ?: $this->request->input('username')
            ?: 'guest';

        $metadata = array_merge([
            'method' => $this->request->method(),
            'url' => $this->request->fullUrl(),
            'path' => $this->request->path(),
            'route' => $this->request->route()?->getName(),
            'headers' => [
                'x-forwarded-for' => $this->request->header('x-forwarded-for'),
                'cf-connecting-ip' => $this->request->header('cf-connecting-ip'),
                'origin' => $this->request->header('origin'),
                'referer' => $this->request->header('referer'),
            ],
            'query' => $this->request->query(),
        ], $this->extraMetadata);

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
