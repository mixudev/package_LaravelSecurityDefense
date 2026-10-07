<?php
declare(strict_types=1);
namespace Mixudev\SecurityDefense\Tests\Feature\Adversarial\Dashboard;
use PHPUnit\Framework\Attributes\DataProvider;
use Illuminate\Auth\GenericUser;
use Illuminate\Support\Facades\Auth;
use Mixudev\SecurityDefense\Tests\TestCase;
final class DashboardRouteMatrixTest extends TestCase {
 use DashboardHarness;
 protected function setUp(): void { parent::setUp(); $this->setUpDashboard(); }
 // Every registered dashboard route, GET and POST, sits behind the same
 // gateway. Correct verbs are used so a 405 can never masquerade as a deny.
 public static function routes(): array { return [
  ['GET','/security-defense'],['GET','/security-defense/data-audits'],['GET','/security-defense/sessions'],['GET','/security-defense/epistemic'],['GET','/security-defense/live-events'],
  ['POST','/security-defense/epistemic/feedback'],['POST','/security-defense/test-channel'],['POST','/security-defense/alerts/1/acknowledge'],['POST','/security-defense/alerts/1/resolve'],['POST','/security-defense/quarantine/pardon'],['POST','/security-defense/quarantine/whitelist'],['POST','/security-defense/toggle-setting'],
 ]; }
 #[DataProvider('routes')] public function test_every_dashboard_route_denies_anonymous_access(string $method,string $path): void {
  $token='adversarial-csrf-token';
  $status=$this->withSession(['_token'=>$token])->withServerVariables(['REMOTE_ADDR'=>'127.0.0.1'])->withHeaders(['Accept'=>'application/json'])->call($method,$path,['_token'=>$token])->getStatusCode();
  $this->assertSame(403,$status,$method.' '.$path.' must be forbidden for anonymous users');
 }
 #[DataProvider('routes')] public function test_client_side_role_never_authorizes_any_route(string $method,string $path): void {
  config()->set('security-defense.dashboard.authorization',['enabled'=>true,'mode'=>'role','roles'=>['admin']]);
  Auth::setUser(new GenericUser(['id'=>8,'roles'=>['user']]));
  $token='adversarial-csrf-token';
  $status=$this->withSession(['_token'=>$token])->withServerVariables(['REMOTE_ADDR'=>'127.0.0.1'])->withHeaders(['Accept'=>'application/json'])->call($method,$path.'?role=admin&permission=dashboard',['_token'=>$token])->getStatusCode();
  $this->assertSame(403,$status,$method.' '.$path.' must ignore client-supplied role');
 }
}
