<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Console\Commands;

use Illuminate\Console\Command;
use Mixudev\SecurityDefense\Services\TelegramBotService;
use Throwable;

/**
 * Artisan command to poll Telegram Bot API for incoming commands and inline button clicks.
 * Allows interactive Telegram Bot testing and operation in local dev environments without a public webhook URL.
 */
class TelegramPollCommand extends Command
{
    /**
     * The name and signature of the console command.
     */
    protected $signature = 'security:telegram-poll
                            {--timeout=25 : Polling timeout in seconds}
                            {--sleep=1 : Sleep duration between polling loops in seconds}
                            {--once : Execute a single polling query and exit}';

    /**
     * The console command description.
     */
    protected $description = 'Poll Telegram Bot updates for interactive commands, health checks, and inline button menus';

    /**
     * Execute the console command.
     */
    public function handle(TelegramBotService $botService): int
    {
        if (!$botService->isInteractiveEnabled()) {
            $this->error('Telegram Bot is not enabled or bot token is missing.');
            $this->line('Ensure SECURITY_TELEGRAM_ENABLED=true and SECURITY_TELEGRAM_BOT_TOKEN is set in your .env file.');
            return self::FAILURE;
        }

        $timeout = (int) $this->option('timeout');
        $sleep = (int) $this->option('sleep');
        $once = (bool) $this->option('once');

        $this->info('Security Defense Telegram Bot Poller active.');
        $this->line('Listening for updates (/start, /health, /metrics, button clicks)...');
        $this->line('Press Ctrl+C to terminate.');

        $offset = 0;

        do {
            try {
                $updates = $botService->getUpdates($offset, $timeout);

                foreach ($updates as $update) {
                    $updateId = (int) ($update['update_id'] ?? 0);
                    if ($updateId >= $offset) {
                        $offset = $updateId + 1;
                    }

                    $type = isset($update['callback_query']) ? 'callback_query' : (isset($update['message']) ? 'message' : 'unknown');
                    $sender = $update['message']['from']['username'] ?? ($update['callback_query']['from']['username'] ?? 'anonymous');

                    $this->comment(sprintf('[%s] Received %s from @%s', date('H:i:s'), $type, $sender));

                    $botService->handleUpdate($update);
                }
            } catch (Throwable $e) {
                $this->error('Error during Telegram update poll: ' . $e->getMessage());
            }

            if ($once) {
                break;
            }

            if ($sleep > 0) {
                sleep($sleep);
            }
        } while (true);

        return self::SUCCESS;
    }
}
