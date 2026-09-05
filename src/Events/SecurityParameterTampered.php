<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;
use Mixudev\SecurityDefense\Models\SecurityDataAudit;

/**
 * Event fired when an HTTP parameter tampering / mass-assignment bypass is detected.
 */
class SecurityParameterTampered
{
    use Dispatchable, SerializesModels;

    /**
     * @param SecurityDataAudit $audit
     * @param array<string> $reasons
     */
    public function __construct(
        public readonly SecurityDataAudit $audit,
        public readonly array $reasons = []
    ) {
    }
}
