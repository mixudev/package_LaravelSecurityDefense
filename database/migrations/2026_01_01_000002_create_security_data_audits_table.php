<?php

declare(strict_types=1);

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
        $table = (string) config('security-defense.data_audit.table', 'security_data_audits');

        if (! Schema::hasTable($table)) {
            Schema::create($table, function (Blueprint $blueprint) {
                $blueprint->id();
                $blueprint->string('event', 20); // created, updated, deleted, restored
                $blueprint->string('auditable_type', 191);
                $blueprint->string('auditable_id', 64);
                $blueprint->string('actor_id', 64)->nullable();
                $blueprint->string('actor_type', 191)->nullable();
                $blueprint->string('ip_address', 45)->default('127.0.0.1');
                $blueprint->text('user_agent')->nullable();
                $blueprint->text('request_url')->nullable();
                $blueprint->string('request_method', 10)->default('CLI');
                $blueprint->string('request_route', 191)->nullable();
                $blueprint->json('old_values')->nullable();
                $blueprint->json('new_values')->nullable();
                $blueprint->json('modified_fields')->nullable();
                $blueprint->json('payload_snapshot')->nullable();
                $blueprint->boolean('is_tampered')->default(false);
                $blueprint->json('tamper_reasons')->nullable();
                $blueprint->timestamps();

                $blueprint->index(['auditable_type', 'auditable_id'], 'idx_auditable');
                $blueprint->index('actor_id', 'idx_actor');
                $blueprint->index('event', 'idx_event');
                $blueprint->index('is_tampered', 'idx_tampered');
                $blueprint->index('created_at', 'idx_created_at');
            });
        }
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        $table = (string) config('security-defense.data_audit.table', 'security_data_audits');
        Schema::dropIfExists($table);
    }
};
