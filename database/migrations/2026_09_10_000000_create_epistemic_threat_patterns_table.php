<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        if (!Schema::hasTable('epistemic_threat_patterns')) {
            Schema::create('epistemic_threat_patterns', function (Blueprint $table) {
                $table->id();
                $table->string('pattern_key', 64)->unique()->index();
                $table->string('hypothesis', 64);
                $table->float('confidence')->default(0.5);
                $table->unsignedInteger('true_positive_count')->default(0);
                $table->unsignedInteger('false_positive_count')->default(0);
                $table->string('last_outcome', 30)->nullable();
                $table->timestamp('last_seen_at')->nullable();
                $table->timestamps();
            });
        }
    }

    public function down(): void
    {
        Schema::dropIfExists('epistemic_threat_patterns');
    }
};
