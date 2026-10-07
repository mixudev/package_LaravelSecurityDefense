<?php
declare(strict_types=1);
namespace Mixudev\SecurityDefense\Tests\Feature\Adversarial\Dashboard;
use PHPUnit\Framework\Attributes\DataProvider;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Auth\GenericUser;
use Mixudev\SecurityDefense\Tests\TestCase;
final class CustomResolverAdversarialTest extends TestCase {
 use DashboardHarness;
 protected function setUp(): void { parent::setUp(); $this->setUpDashboard(); }
 // Only an explicit boolean true may authorize. Truthy coercion (strings,
 // ints, arrays, objects) from a sloppy or hostile resolver must deny.
 public static function denyTypes(): array { return [
  'null'=>[null],'false'=>[false],'zero'=>[0],'one'=>[1],'string_true'=>['true'],'string_admin'=>['admin'],'string_falsey'=>['false'],'array'=>[['admin']],'empty_array'=>[[]],'object'=>[new \stdClass()],'float'=>[123.45],
 ]; }
 #[DataProvider('denyTypes')] public function test_custom_resolver_non_boolean_results_fail_closed(mixed $ret): void {
  $resolver=new class($ret){ public function __construct(private mixed $v){} public function __invoke($u,$req,$cfg): mixed { return $this->v; } };
  $this->app->instance('adversarial.resolver',$resolver);
  $this->assertFalse($this->serviceAllows(['enabled'=>true,'mode'=>'custom','resolver'=>'adversarial.resolver']),'Resolver result of type '.get_debug_type($ret).' must not authorize');
 }
 public function test_custom_resolver_explicit_true_authorizes_authenticated_user(): void {
  $resolver=new class{ public function __invoke($u,$req,$cfg): bool { return true; } };
  $this->app->instance('allowing.resolver',$resolver);
  $this->assertTrue($this->serviceAllows(['enabled'=>true,'mode'=>'custom','resolver'=>'allowing.resolver']));
 }
 public function test_throwing_custom_resolver_is_denied(): void {
  $resolver=new class{ public function __invoke($u,$req,$cfg): bool { throw new \BadMethodCallException('boom'); } };
  $this->app->instance('throwing.resolver',$resolver);
  $this->assertFalse($this->serviceAllows(['enabled'=>true,'mode'=>'custom','resolver'=>'throwing.resolver']));
 }
 public function test_resolver_raising_authorization_exception_is_denied(): void {
  $resolver=new class{ public function __invoke($u,$req,$cfg): bool { throw new AuthorizationException(); } };
  $this->app->instance('authz.resolver',$resolver);
  $this->assertFalse($this->serviceAllows(['enabled'=>true,'mode'=>'custom','resolver'=>'authz.resolver']));
 }
 // The resolver receives the server-side authenticated user, never a user
 // reconstructed from request input.
 public function test_resolver_receives_server_side_user(): void {
  $spy=new class{ public mixed $seen=null; public function __invoke($u,$req,$cfg): bool { $this->seen=$u; return false; } };
  $this->app->instance('spy.resolver',$spy);
  $this->assertFalse($this->serviceAllows(['enabled'=>true,'mode'=>'custom','resolver'=>'spy.resolver'],['id'=>42]));
  $this->assertInstanceOf(GenericUser::class,$spy->seen);
  $this->assertEquals(42,$spy->seen->getAuthIdentifier());
 }
}
