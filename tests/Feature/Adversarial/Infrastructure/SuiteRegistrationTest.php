<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature\Adversarial\Infrastructure;

use Mixudev\SecurityDefense\Tests\TestCase;

/**
 * A green suite that silently skips a directory is worse than no suite.
 *
 * This guard proves every adversarial directory is registered with the running
 * PHPUnit configuration AND that each directory actually contains tests. A
 * non-recursive or empty collector reports success over nothing, so every
 * assertion here also requires a non-zero file count.
 */
class SuiteRegistrationTest extends TestCase
{
    /**
     * @var array<string, int>
     */
    private const DIRECTORY_MINIMUMS = [
        'tests/Feature/Adversarial/Infrastructure' => 1,
        'tests/Feature/Adversarial/Waf' => 1,
    ];

    public function test_each_adversarial_directory_contains_at_least_one_test_file(): void
    {
        foreach (self::DIRECTORY_MINIMUMS as $directory => $minimum) {
            $root = dirname(__DIR__, 4) . '/' . $directory;
            $found = $this->collectTestFiles($root);

            $this->assertGreaterThan(
                0,
                count($found),
                "Adversarial directory {$directory} collected zero test files. "
                . 'A recursive collector is required; a non-recursive glob reports success over nothing.'
            );

            $this->assertGreaterThanOrEqual(
                $minimum,
                count($found),
                "Adversarial directory {$directory} has fewer test files than expected."
            );
        }
    }

    public function test_recursive_collection_finds_nested_test_files(): void
    {
        $root = dirname(__DIR__, 4) . '/tests';
        $flatOnly = glob($root . '/*.php') ?: [];
        $recursive = $this->collectTestFiles($root);

        $this->assertGreaterThan(
            0,
            count($recursive),
            'Recursive collection must find test files under tests/.'
        );

        // The naive non-recursive glob finds only tests/TestCase.php, proving
        // the recursive collector is the one doing the work.
        $this->assertLessThan(
            count($recursive),
            count($flatOnly),
            'Recursive collection is not actually recursing; flat and recursive counts are identical.'
        );
    }

    public function test_adversarial_tests_are_reachable_by_the_configured_phpunit_testsuites(): void
    {
        $xml = file_get_contents(dirname(__DIR__, 4) . '/phpunit.xml');
        $this->assertIsString($xml);

        $this->assertStringContainsString('./tests/Feature', $xml);
        $this->assertStringContainsString('./tests/Unit', $xml);
        $this->assertStringContainsString('suffix="Test.php"', $xml);

        // Suites are directories, not single files: a <file> entry would not
        // pick up nested adversarial folders.
        $this->assertStringNotContainsString('<file>', $xml);
    }

    /**
     * @return list<string>
     */
    private function collectTestFiles(string $root): array
    {
        if (!is_dir($root)) {
            return [];
        }

        $found = [];
        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS)
        );

        foreach ($iterator as $file) {
            if ($file->isFile() && str_ends_with($file->getFilename(), 'Test.php')) {
                $found[] = $file->getPathname();
            }
        }

        return $found;
    }
}
