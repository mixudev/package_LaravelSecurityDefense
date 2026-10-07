<?php
declare(strict_types=1);
namespace Mixudev\SecurityDefense\Tests\Feature\Adversarial\Dashboard;

use PHPUnit\Framework\Attributes\DataProvider;
use Illuminate\Auth\GenericUser; use Illuminate\Support\Facades\Auth; use Mixudev\SecurityDefense\Tests\TestCase;
final class ClientRoleInjectionTest extends TestCase { use DashboardHarness;
 protected function setUp(): void { parent::setUp(); $this->setUpDashboard(); config()->set("security-defense.dashboard.authorization",["enabled"=>true,"mode"=>"role","roles"=>["admin"],"role_attribute"=>"roles"]); Auth::setUser(new GenericUser(["id"=>9,"roles"=>["user"]])); }
 public static function vectors(): array { $v=[]; foreach(["role","roles","permission","is_admin","admin"] as $k) foreach(["admin",["admin"],"1",true] as $x) $v[]=[$k,$x]; return $v; }
 #[DataProvider('vectors')] public function test_query_role_and_permission_values_never_escalate(string $key,mixed $value): void { $this->getDashboard("/security-defense?".http_build_query([$key=>$value]),["Accept"=>"application/json"])->assertForbidden(); }
 public static function users(): array { return [[["id"=>1,"roles"=>[]]],[["id"=>2,"roles"=>["user"]]],[["id"=>3,"roles"=>["operator"]]],[["id"=>4]],[["id"=>5,"roles"=>null]]]; }
 #[DataProvider('users')] public function test_server_side_non_admin_users_remain_denied(array $user): void { Auth::setUser(new GenericUser($user)); $this->getDashboard("/security-defense?role=admin",["Accept"=>"application/json"])->assertForbidden(); }
}
