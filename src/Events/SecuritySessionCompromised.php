<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

/**
 * Event fired when a user session shows signs of compromise (e.g. cookie theft via malware infostealer).
 */
class SecuritySessionCompromised
{
    use Dispatchable, SerializesModels;

    /**
     * @param string $userId
     * @param string $ip
     * @param string $reason
     * @param array<string, mixed> $context
     */
    public function __construct(
        public readonly string $userId,
        public readonly string $ip,
        public readonly string $reason,
        public readonly array $context = []
    ) {
    }
}
