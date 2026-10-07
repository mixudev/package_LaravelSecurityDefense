<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Mixudev\SecurityDefense\Models\SecurityDataAudit;
use Mixudev\SecurityDefense\Tests\TestCase;

/**
 * The create migration gained a required `audit_key` column, but migrations only
 * run once. An existing installation that already ran the original create
 * migration never receives the column, so every subsequent data-audit write
 * fails with an "unknown column" SQL error — a silent availability regression
 * for upgraders, invisible to a green suite that always starts from a fresh DB.
 */
class AuditKeyUpgradeMigrationTest extends TestCase
{
    private const TABLE = 'security_data_audits';

    private const UPGRADE_MIGRATION = __DIR__ . '/../../database/migrations/'
        . '2026_01_01_000003_add_audit_key_to_security_data_audits_table.php';

    public function test_upgrade_migration_adds_audit_key_to_a_legacy_table(): void
    {
        $this->simulateLegacyInstall();

        $this->assertFileExists(
            self::UPGRADE_MIGRATION,
            'Existing installations need a dedicated upgrade migration; the create '
            . 'migration only affects fresh databases.'
        );

        $migration = require self::UPGRADE_MIGRATION;
        $migration->up();

        $this->assertTrue(
            Schema::hasColumn(self::TABLE, 'audit_key'),
            'Upgrade migration did not add audit_key to a legacy table.'
        );
    }

    public function test_upgrade_migration_is_idempotent(): void
    {
        $this->simulateLegacyInstall();

        $migration = require self::UPGRADE_MIGRATION;
        $migration->up();
        $migration->up();

        $this->assertTrue(Schema::hasColumn(self::TABLE, 'audit_key'));
    }

    public function test_queued_retry_deduplicates_on_audit_key_after_upgrade(): void
    {
        $this->simulateLegacyInstall();

        $migration = require self::UPGRADE_MIGRATION;
        $migration->up();

        $key = str_repeat('a', 64);
        $attributes = [
            'event' => 'created',
            'auditable_type' => 'App\\Models\\User',
            'auditable_id' => '1',
        ];

        $first = SecurityDataAudit::query()->firstOrCreate(['audit_key' => $key], $attributes);
        $second = SecurityDataAudit::query()->firstOrCreate(['audit_key' => $key], $attributes);

        $this->assertSame($first->id, $second->id, 'Retry of the same audit row must not duplicate it.');
    }

    public function test_legacy_rows_without_audit_key_survive_the_upgrade(): void
    {
        $this->simulateLegacyInstall();

        $migration = require self::UPGRADE_MIGRATION;
        $migration->up();

        // Rows written before the upgrade have no key. A NOT NULL column would
        // make the ALTER fail or force a backfill that invents identity.
        $column = collect(Schema::getColumns(self::TABLE))->firstWhere('name', 'audit_key');

        $this->assertNotNull($column, 'audit_key column is missing after the upgrade.');
        $this->assertTrue(
            (bool) ($column['nullable'] ?? false),
            'audit_key must be nullable so pre-upgrade rows remain valid.'
        );

        foreach ([1, 2] as $id) {
            DB::table(self::TABLE)->insert([
                'event' => 'updated',
                'auditable_type' => 'App\\Models\\User',
                'auditable_id' => (string) $id,
                'created_at' => now(),
                'updated_at' => now(),
            ]);
        }

        $this->assertSame(2, DB::table(self::TABLE)->whereNull('audit_key')->count());
    }

    /**
     * Drop the column so the table matches the shape shipped before this change.
     */
    private function simulateLegacyInstall(): void
    {
        Schema::table(self::TABLE, function (Blueprint $blueprint): void {
            $blueprint->dropUnique(['audit_key']);
            $blueprint->dropColumn('audit_key');
        });

        $this->assertFalse(
            Schema::hasColumn(self::TABLE, 'audit_key'),
            'Could not simulate a pre-upgrade installation.'
        );
    }
}
