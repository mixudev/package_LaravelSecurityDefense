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
 *
 * Security note: the webhook secret is derived deterministically from the
 * bot token (`getWebhookSecret()`). A null secret means the bot token is
 * missing — the endpoint MUST fail closed (401) instead of accepting the
 * payload, otherwise the webhook becomes an open forgery surface.
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

        // Fail-closed: a null/empty expected secret (e.g. missing bot token)
        // MUST reject, never silently accept payloads.
        $expectedSecret = $botService->getWebhookSecret();
        if (!is_string($expectedSecret) || $expectedSecret === '') {
            Log::warning('SecurityDefense: Telegram webhook secret is not configured; ignoring update.');
            return response()->json(['ok' => false, 'error' => 'Unauthorized'], 401);
        }

        $incomingSecret = $request->header('X-Telegram-Bot-Api-Secret-Token');
        if (!is_string($incomingSecret) || !hash_equals($expectedSecret, $incomingSecret)) {
            Log::warning('SecurityDefense: Invalid Telegram webhook secret token received.');
            return response()->json(['ok' => false, 'error' => 'Unauthorized'], 401);
        }

        $payload = $request->json()->all();

        if (empty($payload)) {
            return response()->json(['ok' => false, 'error' => 'Empty payload'], 400);
        }

        $botService->handleUpdate($payload);

        return response()->json(['ok' => true]);
    }
}
