<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature\Adversarial\Audit;

use PHPUnit\Framework\Attributes\DataProvider;
use Mixudev\SecurityDefense\Tests\TestCase;

class ViewSourceAndCspArmorTest extends TestCase
{
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app['config']->set('app.key', 'base64:7VzK9gG2e+x8UfXoN9uC7x/2j6yD8Hw0Z1A2B3C4D5E=');
        $app['config']->set('security-defense.dashboard.enabled', true);
        $app['config']->set('security-defense.dashboard.local_only', true);
        config()->set('security-defense.dashboard.allowed_ips', ['127.0.0.1', '::1']);
        config()->set('security-defense.dashboard.require_authenticated_user', false);
        // Testbench boots with APP_ENV=testing; local mode keys on env 'local'.
        $this->app['env'] = 'local';
    }

    public function test_every_blade_view_uses_escaped_output_only(): void
    {
        $files = $this->bladeFiles(dirname(__DIR__, 4) . '/resources/views');
        $this->assertNotEmpty($files);
        foreach ($files as $file) {
            $this->assertStringNotContainsString('{!!', (string) file_get_contents($file), $file);
        }
    }

    #[DataProvider('hostileMarkerProvider')]
    public function test_view_source_contains_no_unescaped_hostile_sink(string $marker): void
    {
        $files = $this->bladeFiles(dirname(__DIR__, 4) . '/resources/views');
        $source = '';
        foreach ($files as $file) $source .= (string) file_get_contents($file);
        $this->assertStringNotContainsString('{!!', $source);
        $this->assertStringNotContainsString($marker, strtolower($source));
    }

    #[DataProvider('dashboardProvider')]
    public function test_dashboard_response_has_nonce_csp(string $path): void
    {
        config()->set('security-defense.dashboard.require_authenticated_user', false);
        config()->set('security-defense.dashboard.local_only', true);
        // Testbench boots with APP_ENV=testing; local mode keys on env 'local'.
        $this->app['env'] = 'local';
        // CSP armor is documented as host opt-in (SKILL.md: append to the HTTP
        // kernel); reproduce that wiring so the assertion covers the real path.
        $this->app->make(\Illuminate\Contracts\Http\Kernel::class)
            ->pushMiddleware(\Mixudev\SecurityDefense\Middleware\ContentSecurityPolicyArmor::class);

        $response = $this->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])->get($path);
        $this->assertSame(200, $response->getStatusCode(), $path);
        $csp = (string) $response->headers->get('Content-Security-Policy');
        $this->assertStringContainsString('script-src', $csp);
        $this->assertStringContainsString("'nonce-", $csp);
        // The rendered modal script must carry the SAME nonce the header declares,
        // otherwise the policy would block the package's own dashboard script.
        $this->assertMatchesRegularExpression('/<script nonce="[A-Za-z0-9+\/=]+">/', (string) $response->getContent());
    }

    /** @return array<string,array{0:string}> */
    public static function hostileMarkerProvider(): array
    {
        return [
            'raw output' => ['{!!'], 'raw html' => ['{!! $'],
            'raw echo' => ['{!! echo'], 'raw json' => ['{!! json_encode'],
        ];
    }

    /** @return list<string> */
    private function bladeFiles(string $directory): array
    {
        $files = [];
        $iterator = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($directory));
        foreach ($iterator as $file) {
            if ($file->isFile() && $file->getExtension() === 'php') $files[] = $file->getPathname();
        }
        return $files;
    }

    /** @return array<string,array{0:string}> */
    public static function dashboardProvider(): array
    {
        return ['audits' => ['/security-defense/data-audits'], 'sessions' => ['/security-defense/sessions']];
    }
}
