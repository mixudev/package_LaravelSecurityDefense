<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Jobs;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Mixudev\SecurityDefense\Events\SecurityParameterTampered;
use Mixudev\SecurityDefense\Models\SecurityDataAudit;
use Mixudev\SecurityDefense\Services\DataAuditService;
use Throwable;

/**
 * Background job to process and persist security data audit records asynchronously,
 * ensuring zero request latency impact for high-traffic environments.
 */
class ProcessSecurityDataAuditJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    /**
     * @param array<string, mixed> $auditData
     */
    public function __construct(
        public readonly array $auditData
    ) {
    }

    /**
     * Execute the job.
     */
    public function handle(DataAuditService $auditService): void
    {
        try {
            /** @var SecurityDataAudit $audit */
            $audit = SecurityDataAudit::query()->create($this->auditData);

            if ($audit->is_tampered) {
                event(new SecurityParameterTampered($audit, $audit->tamper_reasons ?? []));

                if (config('security-defense.data_audit.alert_on_tampering', true)) {
                    $auditService->dispatchTamperAlert($audit, $audit->tamper_reasons ?? []);
                }
            }
        } catch (Throwable $e) {
            report($e);
        }
    }
}
