<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Log;
use Mixudev\SecurityDefense\Services\TelegramBotService;

/**
 * Controller handling incoming webhooks from Telegram Bot API.
 */
class TelegramWebhookController extends Controller
{
    /**
     * Handle incoming webhook update from Telegram Bot.
     */
    public function __invoke(Request $request, TelegramBotService $botService): JsonResponse
    {
        if (!$botService->isInteractiveEnabled()) {
            return response()->json(['ok' => false, 'error' => 'Interactive bot disabled'], 403);
        }

        // Validate automatically derived webhook secret token
        $expectedSecret = $botService->getWebhookSecret();
        if (filled($expectedSecret)) {
            $incomingSecret = $request->header('X-Telegram-Bot-Api-Secret-Token');
            if ($incomingSecret !== $expectedSecret) {
                Log::warning('SecurityDefense: Invalid Telegram webhook secret token received.');
                return response()->json(['ok' => false, 'error' => 'Unauthorized'], 401);
            }
        }

        $payload = $request->json()->all();

        if (empty($payload)) {
            return response()->json(['ok' => false, 'error' => 'Empty payload'], 400);
        }

        $botService->handleUpdate($payload);

        return response()->json(['ok' => true]);
    }
}
