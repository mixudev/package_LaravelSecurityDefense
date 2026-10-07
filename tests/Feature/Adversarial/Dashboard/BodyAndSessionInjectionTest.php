<?php
declare(strict_types=1);
namespace Mixudev\SecurityDefense\Tests\Feature\Adversarial\Dashboard;
use PHPUnit\Framework\Attributes\DataProvider;
use Illuminate\Support\Facades\Auth;
use Illuminate\Auth\GenericUser;
use Mixudev\SecurityDefense\Tests\TestCase;
final class BodyAndSessionInjectionTest extends TestCase {
 use DashboardHarness;
 protected function setUp(): void { parent::setUp(); $this->setUpDashboard(); }
 // POST body fields: the authorization service must derive the decision from
 // the server-side user only, whatever the request body claims.
 public static function bodies(): array { $v=[]; foreach(['role','permission','is_admin','user_role','ability'] as $k) foreach(['admin',true,1,['admin'],json_encode(['admin'=>true])] as $x) $v[$k.'|'.json_encode($x)]=[$k,$x]; return $v; }
 #[DataProvider('bodies')] public function test_body_values_cannot_authorize(string $key,mixed $value): void { $this->assertFalse($this->serviceAllows(['enabled'=>true,'mode'=>'role','roles'=>['admin']],['id'=>3,'roles'=>['user']],[$key=>$value])); }
 public static function sessionValues(): array { return ['string'=>['admin'],'array'=>[['role'=>'admin']],'permissions'=>[['permissions'=>['dashboard']]],'bool'=>[true],'int'=>[1],'null'=>[null]]; }
 #[DataProvider('sessionValues')] public function test_session_tampering_does_not_replace_server_side_user(mixed $value): void { $this->withSession(['role'=>$value,'is_admin'=>true,'permissions'=>['dashboard']]); $this->assertFalse($this->serviceAllows(['enabled'=>true,'mode'=>'role','roles'=>['admin']],['id'=>3,'roles'=>['user']])); }
 // Even a fully privileged server-side user is still only one half of the
 // contract: the HTTP layer must keep enforcing authentication first.
 public function test_http_session_role_claim_is_not_a_grant(): void { Auth::setUser(new GenericUser(['id'=>3,'roles'=>['user']])); config()->set('security-defense.dashboard.authorization',['enabled'=>true,'mode'=>'role','roles'=>['admin']]); $this->withSession(['role'=>'admin','is_admin'=>1]); $this->getDashboard('/security-defense',['Accept'=>'application/json'])->assertForbidden(); }
}
