<?php
declare(strict_types=1);
namespace Mixudev\SecurityDefense\Tests\Feature\Adversarial\Dashboard;
use PHPUnit\Framework\Attributes\DataProvider;
use Illuminate\Auth\GenericUser;
use Illuminate\Support\Facades\Gate;
use Mixudev\SecurityDefense\Tests\TestCase;
final class GateFailureTest extends TestCase {
 use DashboardHarness;
 protected function setUp(): void { parent::setUp(); $this->setUpDashboard(); }
 // Gate name comes from server-side config only; malformed or unregistered
 // names must deny rather than throw or fall through to allow.
 public static function badGateNames(): array { return [[null],[''],[123],[[]],[new \stdClass()],['gate-that-is-not-registered']]; }
 #[DataProvider('badGateNames')] public function test_missing_or_malformed_gate_names_deny(mixed $name): void { $this->assertFalse($this->serviceAllows(['enabled'=>true,'mode'=>'gate','name'=>$name])); }
 public function test_gate_that_throws_is_denied(): void { Gate::define('throws',fn()=>throw new \RuntimeException('failure')); $this->assertFalse($this->serviceAllows(['enabled'=>true,'mode'=>'gate','name'=>'throws'])); }
 public function test_gate_returning_false_is_denied(): void { Gate::define('deny',fn()=>false); $this->assertFalse($this->serviceAllows(['enabled'=>true,'mode'=>'gate','name'=>'deny'])); }
 public function test_gate_true_allows_authenticated_user(): void { Gate::define('allow',fn($u)=>$u instanceof GenericUser); $this->assertTrue($this->serviceAllows(['enabled'=>true,'mode'=>'gate','name'=>'allow'])); }
 public function test_gate_true_cannot_apply_to_a_missing_user(): void { Gate::define('allow',fn($u)=>$u instanceof GenericUser); $this->assertFalse($this->serviceAllows(['enabled'=>true,'mode'=>'gate','name'=>'allow'],[])); }
}
