<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Console\Commands;

use Illuminate\Console\Command;
use Mixudev\SecurityDefense\Models\SecurityAlert;
use Mixudev\SecurityDefense\Models\SecurityDataAudit;

/**
 * Artisan command to prune stale security alerts and database audit logs.
 */
class PruneSecurityDataCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'security-defense:prune
                            {--days= : Override default retention days for normal records}
                            {--tampered-days= : Override default retention days for tampered audit records}
                            {--dry-run : Display count of records to be pruned without deleting}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Prune old security alerts and audit logs according to retention policies';

    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        $this->info('[SecurityDefense] Starting security records pruning...');

        $normalDays = $this->option('days') !== null
            ? (int) $this->option('days')
            : (int) config('security-defense.data_audit.retention_days', 30);

        $tamperedDays = $this->option('tampered-days') !== null
            ? (int) $this->option('tampered-days')
            : (int) config('security-defense.data_audit.tampered_retention_days', 90);

        $alertDays = (int) config('security-defense.alerts.retention_days', 60);

        $dryRun = (bool) $this->option('dry-run');

        // 1. Prune normal audits
        $normalAuditQuery = SecurityDataAudit::where('is_tampered', false)
            ->where('created_at', '<=', now()->subDays($normalDays));

        $normalAuditCount = $normalAuditQuery->count();

        // 2. Prune tampered audits
        $tamperedAuditQuery = SecurityDataAudit::where('is_tampered', true)
            ->where('created_at', '<=', now()->subDays($tamperedDays));

        $tamperedAuditCount = $tamperedAuditQuery->count();

        // 3. Prune resolved/old security alerts
        $alertsQuery = SecurityAlert::where('created_at', '<=', now()->subDays($alertDays));
        $alertsCount = $alertsQuery->count();

        if ($dryRun) {
            $this->warn('[DRY-RUN] No records will be deleted.');
            $this->table(
                ['Category', 'Cutoff Date', 'Records Matched'],
                [
                    ['Normal Data Audits', now()->subDays($normalDays)->toDateTimeString(), $normalAuditCount],
                    ['Tampered Data Audits', now()->subDays($tamperedDays)->toDateTimeString(), $tamperedAuditCount],
                    ['Security Alerts', now()->subDays($alertDays)->toDateTimeString(), $alertsCount],
                ]
            );

            return self::SUCCESS;
        }

        $deletedNormal = $normalAuditQuery->delete();
        $deletedTampered = $tamperedAuditQuery->delete();
        $deletedAlerts = $alertsQuery->delete();

        $this->info("[DONE] Pruned {$deletedNormal} normal audits (older than {$normalDays} days).");
        $this->info("[DONE] Pruned {$deletedTampered} tampered audits (older than {$tamperedDays} days).");
        $this->info("[DONE] Pruned {$deletedAlerts} security alerts (older than {$alertDays} days).");

        return self::SUCCESS;
    }
}
