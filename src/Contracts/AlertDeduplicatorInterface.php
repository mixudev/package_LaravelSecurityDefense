<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Contracts;

use Mixudev\SecurityDefense\DTO\SecurityThreat;

/**
 * Contract for fingerprint-based alert deduplication.
 */
interface AlertDeduplicatorInterface
{
    /**
     * Determine whether a threat should trigger a new alert or be suppressed.
     *
     * @param SecurityThreat $threat
     * @return bool True if alert should be emitted, false if suppressed as duplicate.
     */
    public function shouldAlert(SecurityThreat $threat): bool;

    /**
     * Record a threat fingerprint into deduplication cache window.
     *
     * @param SecurityThreat $threat
     */
    public function record(SecurityThreat $threat): void;

    /**
     * Clear a recorded fingerprint from the deduplication store.
     *
     * @param string $fingerprint
     */
    public function forget(string $fingerprint): void;
}
