<?php
declare(strict_types=1);
namespace Mixudev\SecurityDefense\Tests\Feature\Adversarial\Dashboard;

use PHPUnit\Framework\Attributes\DataProvider;
use Illuminate\Auth\GenericUser; use Illuminate\Support\Facades\Auth; use Mixudev\SecurityDefense\Tests\TestCase;
final class RequestMetadataInjectionTest extends TestCase { use DashboardHarness;
 protected function setUp(): void { parent::setUp(); $this->setUpDashboard(); config()->set("security-defense.dashboard.authorization",["enabled"=>true,"mode"=>"role","roles"=>["admin"]]); Auth::setUser(new GenericUser(["id"=>7,"roles"=>["user"]])); }
 public static function headers(): array { $out=[]; foreach(["X-Role","X-User-Role","X-Permission","X-Admin","Authorization","X-Forwarded-User"] as $k) foreach(["admin","role=admin","Bearer admin",json_encode(["role"=>"admin"])] as $v) $out[]=[$k,$v]; return $out; }
 #[DataProvider('headers')] public function test_headers_never_supply_authority(string $name,string $value): void { $this->getDashboard("/security-defense",["Accept"=>"application/json",$name=>$value])->assertForbidden(); }
 public static function cookies(): array { return array_map(fn($v)=>[$v],["role=admin","admin","permission=dashboard",json_encode(["is_admin"=>true]),"eyJyb2LiOjF9.eyJyb2xlIjoiYWRtaW4ifQ=="]); }
 #[DataProvider('cookies')] public function test_cookies_never_supply_authority(string $cookie): void { $this->withCookie("role",$cookie)->getDashboard("/security-defense",["Accept"=>"application/json"])->assertForbidden(); }
}
