<?php
declare(strict_types=1);
namespace Mixudev\SecurityDefense\Tests\Feature\Adversarial\Dashboard;
use Illuminate\Auth\GenericUser;
use Illuminate\Support\Facades\Auth;
use Mixudev\SecurityDefense\Tests\TestCase;
trait DashboardHarness
{
    protected function setUpDashboard(): void
    {
        $this->app["env"] = "local";
        $this->app["config"]->set("app.key", "base64:7VzK9gG2e+x8UfXoN9uC7x/2j6yD8Hw0Z1A2B3C4D5E=");
        config()->set("security-defense.dashboard.enabled", true);
        config()->set("security-defense.dashboard.local_only", true);
        config()->set("security-defense.dashboard.allowed_ips", ["127.0.0.1", "::1"]);
        config()->set("security-defense.dashboard.require_authenticated_user", true);
        config()->set("security-defense.dashboard.authorization", ["enabled" => false, "mode" => "none", "roles" => [], "role_method" => "hasAnyRole", "role_attribute" => "roles", "name" => null, "resolver" => null]);
    }
    protected function getDashboard(string $path, array $headers = [])
    {
        return $this->withServerVariables(["REMOTE_ADDR" => "127.0.0.1"])->withHeaders($headers)->get($path);
    }
    protected function serviceAllows(array $authorization, array $user = ["id" => 1, "roles" => ["user"]], array $input = []): bool
    {
        $request = request()->create("/security-defense?" . http_build_query($input), "GET", $input, [], [], ["REMOTE_ADDR" => "127.0.0.1"]);
        $request->setUserResolver(fn () => $user === [] ? null : new GenericUser($user));
        return app(\Mixudev\SecurityDefense\Services\DashboardAuthorization::class)->allows($request, $authorization);
    }
}
