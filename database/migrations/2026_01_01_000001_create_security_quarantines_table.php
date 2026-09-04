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
        $tableName = config('security-defense.middleware.quarantine.table', 'security_quarantines');

        if (!Schema::hasTable($tableName)) {
            Schema::create($tableName, function (Blueprint $table) {
                $table->id();
                $table->string('ip', 45)->index(); // Supports IPv6
                $table->timestamp('jailed_at')->nullable();
                $table->timestamp('expires_at')->index();
                $table->string('reason', 255)->nullable();
                $table->timestamps();

                $table->unique('ip');
            });
        }
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        $tableName = config('security-defense.middleware.quarantine.table', 'security_quarantines');
        Schema::dropIfExists($tableName);
    }
};
