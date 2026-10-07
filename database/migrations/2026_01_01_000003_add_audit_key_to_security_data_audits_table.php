<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        $table = (string) config('security-defense.data_audit.table', 'security_data_audits');

        if (! Schema::hasTable($table) || Schema::hasColumn($table, 'audit_key')) {
            return;
        }

        Schema::table($table, function (Blueprint $blueprint): void {
            // Nullable preserves rows written before audit-key idempotency existed.
            $blueprint->string('audit_key', 64)->nullable();
            $blueprint->unique('audit_key');
        });
    }

    public function down(): void
    {
        $table = (string) config('security-defense.data_audit.table', 'security_data_audits');

        if (! Schema::hasTable($table) || ! Schema::hasColumn($table, 'audit_key')) {
            return;
        }

        Schema::table($table, function (Blueprint $blueprint): void {
            $blueprint->dropUnique(['audit_key']);
            $blueprint->dropColumn('audit_key');
        });
    }
};
