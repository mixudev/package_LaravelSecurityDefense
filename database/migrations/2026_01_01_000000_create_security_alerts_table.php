<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        $tableName = config('security-defense.alerts.database.table', 'security_alerts');

        if (!Schema::hasTable($tableName)) {
            Schema::create($tableName, function (Blueprint $table) {
                $table->id();
                $table->string('severity', 20)->index(); // low, medium, high, critical
                $table->string('threat_type', 100)->index();
                $table->string('fingerprint', 64)->index();
                $table->string('status', 30)->default('new')->index(); // new, acknowledged, resolved
                $table->string('rule_identifier', 100)->nullable();
                $table->json('metadata')->nullable();
                $table->timestamp('resolved_at')->nullable();
                $table->timestamps();

                $table->index(['threat_type', 'created_at']);
                $table->index(['fingerprint', 'status']);
            });
        }
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        $tableName = config('security-defense.alerts.database.table', 'security_alerts');
        Schema::dropIfExists($tableName);
    }
};
