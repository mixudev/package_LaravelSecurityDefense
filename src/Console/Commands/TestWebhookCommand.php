<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Console\Commands;

use Illuminate\Console\Command;
use Mixudev\SecurityDefense\Services\ChannelTestService;
use Throwable;

/**
 * Artisan command for securely testing alert channel and webhook connectivity.
 */
class TestWebhookCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'security:test-webhook
                            {channel? : Specific channel to test (webhook, discord, telegram, mail)}
                            {--all : Test all registered channels}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Safely test connectivity and delivery of alert channels or external webhooks';

    /**
     * Execute the console command.
     */
    public function handle(ChannelTestService $testService): int
    {
        $this->info('=== Laravel Security Defense: Channel Connectivity Diagnostic ===');

        $channel = $this->argument('channel');
        $testAll = (bool) $this->option('all');

        try {
            if ($channel !== null) {
                $this->line("Testing single channel: <comment>{$channel}</comment>...");
                $result = $testService->testChannel((string) $channel);
                $this->renderResultTable([$result]);

                return $result['success'] ? self::SUCCESS : self::FAILURE;
            }

            if ($testAll || $channel === null) {
                $this->line('Testing all alert channels...');
                $results = $testService->testAll();
                $this->renderResultTable(array_values($results));

                $allSuccessful = count(array_filter($results, fn($r) => $r['success'])) > 0;

                return $allSuccessful ? self::SUCCESS : self::FAILURE;
            }
        } catch (Throwable $e) {
            $this->error('Error executing channel test: ' . $e->getMessage());

            return self::FAILURE;
        }

        return self::SUCCESS;
    }

    /**
     * Render results as a formatted console table.
     *
     * @param array<int, array{channel: string, success: bool, enabled: bool, configured: bool, latency_ms?: float, message: string}> $results
     */
    protected function renderResultTable(array $results): void
    {
        $headers = ['Channel', 'Enabled', 'Configured', 'Delivery', 'Latency', 'Diagnostic Message'];
        $rows = [];

        foreach ($results as $item) {
            $enabled = $item['enabled'] ? '<info>YES</info>' : '<comment>NO</comment>';
            $configured = $item['configured'] ? '<info>YES</info>' : '<comment>NO</comment>';
            $delivery = $item['success']
                ? '<info>SUCCESS</info>'
                : ($item['enabled'] && $item['configured'] ? '<error>FAILED</error>' : '<comment>SKIPPED</comment>');
            $latency = isset($item['latency_ms']) ? "{$item['latency_ms']} ms" : '-';

            $rows[] = [
                strtoupper($item['channel']),
                $enabled,
                $configured,
                $delivery,
                $latency,
                $item['message'],
            ];
        }

        $this->table($headers, $rows);
    }
}
