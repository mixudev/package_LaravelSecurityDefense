<?php
declare(strict_types=1);
namespace Mixudev\SecurityDefense\Tests\Feature\Adversarial\Dashboard;
use PHPUnit\Framework\Attributes\DataProvider;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Auth\GenericUser;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Gate;
use Mixudev\SecurityDefense\Tests\TestCase;
final class AuthorizationFailClosedTest extends TestCase {
 use DashboardHarness;
 protected function setUp(): void { parent::setUp(); $this->setUpDashboard(); }
 // Every malformed authorization configuration must yield DENY for an
 // authenticated user holding no privileged role.
 public static function malformed(): array { return [
  'unknown_mode'=>[['enabled'=>true,'mode'=>'unknown']],
  'uppercase_mode'=>[['enabled'=>true,'mode'=>'ROLE']],
  'gate_without_name'=>[['enabled'=>true,'mode'=>'gate']],
  'role_without_roles'=>[['enabled'=>true,'mode'=>'role','roles'=>[]]],
  'role_bad_method'=>[['enabled'=>true,'mode'=>'role','roles'=>['admin'],'role_method'=>'nope']],
  'role_method_array'=>[['enabled'=>true,'mode'=>'role','roles'=>['admin'],'role_method'=>['hasAnyRole']]],
  'role_attribute_array'=>[['enabled'=>true,'mode'=>'role','roles'=>['admin'],'role_attribute'=>['roles']]],
  'custom_no_resolver'=>[['enabled'=>true,'mode'=>'custom']],
  'custom_unknown_class'=>[['enabled'=>true,'mode'=>'custom','resolver'=>'MissingResolverClass']],
  'mode_null'=>[['enabled'=>true,'mode'=>null]],
  'mode_empty'=>[['enabled'=>true,'mode'=>'']],
  'mode_array'=>[['enabled'=>true,'mode'=>['role']]],
  'enabled_string_unknown_mode'=>[['enabled'=>'yes','mode'=>'unknown']],
 ]; }
 #[DataProvider('malformed')] public function test_malformed_authorization_configuration_denies(array $config): void { $this->assertFalse($this->serviceAllows($config,['id'=>3,'roles'=>['user']]),'Malformed config must fail closed'); }
 public function test_disabled_authorization_still_requires_an_authenticated_user(): void { $this->assertFalse($this->serviceAllows(['enabled'=>false,'mode'=>'none'],[])); }
 public function test_none_mode_still_requires_an_authenticated_user(): void { $this->assertFalse($this->serviceAllows(['enabled'=>true,'mode'=>'none'],[])); }
 // mode "none" is the shipped no-policy mode: no role check, but it never
 // replaces the authentication requirement above it (auth-first contract).
 public function test_none_mode_with_authenticated_user_is_auth_only(): void { $this->assertTrue($this->serviceAllows(['enabled'=>true,'mode'=>'none'],['id'=>1])); }
 // The classic fail-open bug: an AuthorizationException swallowed must DENY.
 public function test_swallowed_authorization_exception_still_denies(): void { Gate::define('throws-authz',fn()=>throw new AuthorizationException()); $this->assertFalse($this->serviceAllows(['enabled'=>true,'mode'=>'gate','name'=>'throws-authz'])); }
 // Malformed authorization config must surface as a controlled 403 at the
 // HTTP layer: an uncaught cast error would be a 500, not a denial.
 public function test_malformed_mode_over_http_returns_403_not_500(): void {
  config()->set('security-defense.dashboard.authorization',['enabled'=>true,'mode'=>['role']]);
  Auth::setUser(new GenericUser(['id'=>3,'roles'=>['user']]));
  $this->getDashboard('/security-defense',['Accept'=>'application/json'])->assertForbidden();
 }
 public function test_unknown_mode_over_http_returns_403(): void {
  config()->set('security-defense.dashboard.authorization',['enabled'=>true,'mode'=>'admin-bypass']);
  Auth::setUser(new GenericUser(['id'=>3,'roles'=>['admin']]));
  $this->getDashboard('/security-defense',['Accept'=>'application/json'])->assertForbidden();
 }
 public function test_unauthenticated_user_is_denied_in_every_mode(): void { foreach(['none','gate','role','custom','unknown'] as $mode){ $this->assertFalse($this->serviceAllows(['enabled'=>true,'mode'=>$mode,'roles'=>['admin'],'name'=>'viewSecurityDefenseDashboard','resolver'=>'x'],[]),'Anonymous must be denied in mode '.$mode); } }
}
