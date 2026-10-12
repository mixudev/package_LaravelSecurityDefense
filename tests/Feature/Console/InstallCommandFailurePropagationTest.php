<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature\Console;

use Illuminate\Console\Command;
use Symfony\Component\Console\Input\ArrayInput;
use Illuminate\Console\OutputStyle;
use Mixudev\SecurityDefense\Console\Commands\InstallCommand;
use Mixudev\SecurityDefense\Tests\TestCase;
use Symfony\Component\Console\Output\BufferedOutput;

/**
 * security-defense:install must fail closed when any sub-command it drives
 * fails. A silent SUCCESS on a failed route cache build reports protection that
 * is not actually in place.
 */
class InstallCommandFailurePropagationTest extends TestCase
{
    private string $originalConfig;
    private ?string $originalEnv;

    protected function setUp(): void
    {
        parent::setUp();

        $this->originalConfig = (string) file_get_contents(config_path('security-defense.php'));
        $this->originalEnv = is_file(base_path('.env')) ? (string) file_get_contents(base_path('.env')) : null;
        @unlink(base_path('.env'));
    }

    protected function tearDown(): void
    {
        @unlink(config_path('security-defense-overrides.php'));
        file_put_contents(config_path('security-defense.php'), $this->originalConfig);

        if ($this->originalEnv === null) {
            @unlink(base_path('.env'));
        } else {
            file_put_contents(base_path('.env'), $this->originalEnv);
        }

        parent::tearDown();
    }

    public function test_publish_failure_returns_nonzero(): void
    {
        $this->assertSame(Command::FAILURE, $this->runInstall(failOn: ['vendor:publish#0']));
    }

    public function test_migration_failure_returns_nonzero(): void
    {
        $this->assertSame(Command::FAILURE, $this->runInstall(failOn: ['migrate#0'], options: ['--no-cache' => true]));
    }

    public function test_route_clear_failure_returns_nonzero(): void
    {
        $this->assertSame(Command::FAILURE, $this->runInstall(failOn: ['route:clear#0'], options: ['--no-migrate' => true]));
    }

    public function test_config_clear_failure_returns_nonzero(): void
    {
        $this->assertSame(Command::FAILURE, $this->runInstall(failOn: ['config:clear#0'], options: ['--no-migrate' => true]));
    }

    public function test_route_cache_failure_returns_nonzero(): void
    {
        $this->assertSame(Command::FAILURE, $this->runInstall(failOn: ['route:cache#0'], options: ['--no-migrate' => true]));
    }

    public function test_all_steps_succeed_returns_zero(): void
    {
        $this->assertSame(Command::SUCCESS, $this->runInstall(failOn: [], options: ['--no-migrate' => true]));
    }

    /**
     * @param list<string> $failOn Entries of the form "command#index" where
     *                             index is the zero-based invocation counter.
     * @param array<string, bool> $options
     */
    private function runInstall(array $failOn, array $options = []): int
    {
        $command = new class extends InstallCommand {
            /** @var list<string> */
            public array $failOn = [];

            /** @var array<string, int> */
            public array $seen = [];

            public function call($command, array $arguments = [])
            {
                $index = ($this->seen[$command] = ($this->seen[$command] ?? 0) + 1) - 1;

                if (in_array($command . '#' . $index, $this->failOn, true)) {
                    return 1;
                }

                return 0;
            }
        };

        $command->failOn = $failOn;
        $command->setLaravel($this->app);

        $input = new ArrayInput($options);
        $input->setInteractive(false);

        return $command->run($input, new OutputStyle($input, new BufferedOutput()));
    }
}
