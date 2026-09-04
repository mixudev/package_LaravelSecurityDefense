<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Http;
use Mixudev\SecurityDefense\Services\TelegramBotService;
use Throwable;

/**
 * Artisan command to manage Telegram Bot webhook registration with Telegram Bot API.
 */
class TelegramWebhookCommand extends Command
{
    /**
     * The name and signature of the console command.
     */
    protected $signature = 'security:telegram-webhook
                            {action=info : Action to perform: info, set, delete}
                            {--url= : Public HTTPS URL for the webhook (required for set)}';

    /**
     * The command description.
     */
    protected $description = 'Inspect, register, or delete the Telegram Bot webhook with Telegram Bot API';

    /**
     * Execute the console command.
     */
    public function handle(TelegramBotService $botService): int
    {
        $token = $botService->getBotToken();
        if (!$token) {
            $this->error('Telegram bot token is not configured.');
            return self::FAILURE;
        }

        $action = strtolower((string) $this->argument('action'));

        return match ($action) {
            'info' => $this->getWebhookInfo($token),
            'set' => $this->setWebhook($botService, $token),
            'delete' => $this->deleteWebhook($token),
            default => $this->invalidAction($action),
        };
    }

    protected function getWebhookInfo(string $token): int
    {
        try {
            $response = Http::timeout(10)->get(sprintf('https://api.telegram.org/bot%s/getWebhookInfo', $token));
            $data = $response->json();

            if (!$response->successful() || !($data['ok'] ?? false)) {
                $this->error('Failed to retrieve webhook info: ' . ($data['description'] ?? 'Unknown error'));
                return self::FAILURE;
            }

            $info = $data['result'] ?? [];
            $this->info('Telegram Webhook Information:');
            $this->table(
                ['Attribute', 'Value'],
                [
                    ['URL', $info['url'] ?: '(None - Polling Mode)'],
                    ['Custom Certificate', ($info['has_custom_certificate'] ?? false) ? 'Yes' : 'No'],
                    ['Pending Update Count', $info['pending_update_count'] ?? 0],
                    ['Last Error Date', isset($info['last_error_date']) ? date('Y-m-d H:i:s', $info['last_error_date']) : 'None'],
                    ['Last Error Message', $info['last_error_message'] ?? 'None'],
                ]
            );

            return self::SUCCESS;
        } catch (Throwable $e) {
            $this->error('Exception querying webhook info: ' . $e->getMessage());
            return self::FAILURE;
        }
    }

    protected function setWebhook(TelegramBotService $botService, string $token): int
    {
        $url = (string) $this->option('url');

        if (empty($url)) {
            $defaultRoute = url('/security-defense/telegram/webhook');
            $url = (string) $this->ask('Enter your public HTTPS webhook URL', $defaultRoute);
        }

        if (!str_starts_with(strtolower($url), 'https://')) {
            $this->error('Telegram Webhook URL must use HTTPS.');
            return self::FAILURE;
        }

        $secret = $botService->getWebhookSecret();
        $params = [
            'url' => $url,
            'allowed_updates' => json_encode(['message', 'callback_query']),
        ];

        if (filled($secret)) {
            $params['secret_token'] = $secret;
        }

        try {
            $response = Http::timeout(10)->post(sprintf('https://api.telegram.org/bot%s/setWebhook', $token), $params);
            $data = $response->json();

            if ($response->successful() && ($data['ok'] ?? false)) {
                $this->info('Webhook set successfully: ' . $url);
                return self::SUCCESS;
            }

            $this->error('Failed to set webhook: ' . ($data['description'] ?? 'Unknown error'));
            return self::FAILURE;
        } catch (Throwable $e) {
            $this->error('Exception setting webhook: ' . $e->getMessage());
            return self::FAILURE;
        }
    }

    protected function deleteWebhook(string $token): int
    {
        try {
            $response = Http::timeout(10)->post(sprintf('https://api.telegram.org/bot%s/deleteWebhook', $token));
            $data = $response->json();

            if ($response->successful() && ($data['ok'] ?? false)) {
                $this->info('Webhook deleted successfully. Telegram Bot switched back to Polling mode.');
                return self::SUCCESS;
            }

            $this->error('Failed to delete webhook: ' . ($data['description'] ?? 'Unknown error'));
            return self::FAILURE;
        } catch (Throwable $e) {
            $this->error('Exception deleting webhook: ' . $e->getMessage());
            return self::FAILURE;
        }
    }

    protected function invalidAction(string $action): int
    {
        $this->error("Invalid action '{$action}'. Valid actions are: info, set, delete.");
        return self::FAILURE;
    }
}
