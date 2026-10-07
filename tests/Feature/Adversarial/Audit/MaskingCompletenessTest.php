<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature\Adversarial\Audit;

use PHPUnit\Framework\Attributes\DataProvider;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Schema;
use Mixudev\SecurityDefense\Models\SecurityDataAudit;
use Mixudev\SecurityDefense\Support\Traits\HasSecurityAudit;
use Mixudev\SecurityDefense\Tests\TestCase;

class MaskingCompletenessModel extends Model
{
    use HasSecurityAudit;

    protected $table = 'masking_complete_models';
    protected $guarded = [];
    protected $casts = ['balance' => 'integer'];

    public function getSecurityAuditMaskedColumns(): array
    {
        return ['balance', 'external_id'];
    }
}

class MaskingCompletenessTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        config()->set('security-defense.data_audit.alert_on_tampering', false);
        config()->set('security-defense.data_audit.queue.enabled', false);
        Schema::create('masking_complete_models', function (Blueprint $table) {
            $table->id();
            $table->string('email');
            $table->integer('balance')->default(0);
            $table->string('access_token')->nullable();
            $table->string('api_key')->nullable();
            $table->string('private_key')->nullable();
            $table->string('otp')->nullable();
            $table->string('bot_token')->nullable();
            $table->string('webhook_url')->nullable();
            $table->string('external_id')->nullable();
            $table->timestamps();
        });
    }

    #[DataProvider('secretProvider')]
    public function test_secret_never_persisted_plaintext_on_create(string $field, string $value): void
    {
        $model = MaskingCompletenessModel::create(array_merge([
            'email' => 'test@example.com',
            'balance' => 999,
        ], [$field => $value]));

        $audit = $this->getAudit($model, 'created');
        $this->assertStringNotContainsString($value, json_encode($audit->new_values));
        $this->assertArrayHasKey($field, $audit->new_values);
        $this->assertMatchesRegularExpression('/REDACTED|[\\*]{4,}/', (string) $audit->new_values[$field]);
    }

    #[DataProvider('secretProvider')]
    public function test_secret_never_persisted_plaintext_on_update(string $field, string $value): void
    {
        $model = MaskingCompletenessModel::create(['email' => 'test@example.com']);
        $model->update([$field => $value]);

        $audit = $this->getAudit($model, 'updated');
        $this->assertStringNotContainsString($value, json_encode($audit->new_values));
        $this->assertMatchesRegularExpression('/REDACTED|[\\*]{4,}/', (string) $audit->new_values[$field]);
    }

    public function test_model_masked_field_is_masked(): void
    {
        $model = MaskingCompletenessModel::create(['email' => 't@example.com', 'balance' => 4242, 'external_id' => 'ext-123']);
        $audit = $this->getAudit($model, 'created');
        $this->assertStringNotContainsString('4242', json_encode($audit->new_values));
        $this->assertMatchesRegularExpression('/REDACTED|[\\*]{4,}/', (string) $audit->new_values['balance']);
    }

    private function getAudit(Model $model, string $event): SecurityDataAudit
    {
        $audit = SecurityDataAudit::query()
            ->where('auditable_type', get_class($model))
            ->where('auditable_id', (string) $model->getKey())
            ->where('event', $event)
            ->first();
        $this->assertNotNull($audit);
        return $audit;
    }

    /** @return array<string,array{0:string,1:string}> */
    public static function secretProvider(): array
    {
        return [
            'access_token' => ['access_token', 'sk-live-ABCD1234EFGH5678'],
            'api_key' => ['api_key', 'api-XYZ-000-SECRET'],
            'private_key' => ['private_key', '-----BEGIN PRIVATE KEY-----MIIEvgIB...'],
            'otp' => ['otp', '123456'],
            'bot_token' => ['bot_token', '123456:BOT-TOKEN-SECRET-VALUE'],
            'webhook_url' => ['webhook_url', 'https://hooks.example.com/abc123'],
        ];
    }
}
