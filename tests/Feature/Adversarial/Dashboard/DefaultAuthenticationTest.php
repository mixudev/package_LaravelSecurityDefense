<?php
declare(strict_types=1);
namespace Mixudev\SecurityDefense\Tests\Feature\Adversarial\Dashboard;
use PHPUnit\Framework\Attributes\DataProvider;
use Mixudev\SecurityDefense\Tests\TestCase;
final class DefaultAuthenticationTest extends TestCase {
 use DashboardHarness;
 protected function setUp(): void { parent::setUp(); $this->setUpDashboard(); }
 // Pin shipped defaults: a silent flip (authorization on, auth requirement
 // removed, public exposure enabled) would invalidate every other test here.
 public static function defaults(): array { return [
  ['security-defense.dashboard.require_authenticated_user', true], ['security-defense.dashboard.authorization.enabled', false], ['security-defense.dashboard.authorization.mode', 'none'], ['security-defense.dashboard.public.enabled', false], ['security-defense.dashboard.local_only', true], ['security-defense.dashboard.enabled', true],
 ]; }
 #[DataProvider('defaults')] public function test_shipped_defaults_stay_auth_first(string $key,mixed $expected): void { $this->assertSame($expected,config($key)); }
 public static function anonymousRoutes(): array { return array_map(fn($p)=>[$p], ['/security-defense','/security-defense/data-audits','/security-defense/sessions','/security-defense/epistemic','/security-defense/live-events']); }
 #[DataProvider('anonymousRoutes')] public function test_anonymous_dashboard_requests_are_denied(string $path): void { $this->getDashboard($path,['Accept'=>'application/json'])->assertForbidden(); }
 // Routing precedes middleware: an unknown path must never be served with 2xx/3xx.
 public function test_unknown_dashboard_path_is_not_served(): void { $this->assertGreaterThanOrEqual(400,$this->getDashboard('/security-defense/does-not-exist',['Accept'=>'application/json'])->getStatusCode()); }
 // A broken/missing auth guard must degrade to denial, never to a 200/redirect.
 public function test_missing_auth_guard_does_not_allow(): void { config()->set('auth.defaults.guard',null); config()->set('auth.guards',[]); $this->assertNotContains($this->getDashboard('/security-defense',['Accept'=>'application/json'])->getStatusCode(),[200,301,302]); }
}
