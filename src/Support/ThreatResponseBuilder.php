<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Support;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Mixudev\SecurityDefense\DTO\SecurityThreat;

/**
 * Builds minimal HTML or JSON responses for blocked/quarantined requests.
 * Keeps the WAF middleware thin and the block pages consistent.
 */
class ThreatResponseBuilder
{
    /**
     * Build response for quarantined IP.
     */
    public function buildQuarantinedResponse(Request $request, string $ip): Response|JsonResponse
    {
        $status = (int) config('security-defense.middleware.quarantine.response_status', 429);
        $message = (string) config(
            'security-defense.middleware.quarantine.response_message',
            'Your IP has been temporarily quarantined due to suspicious security activity.'
        );

        if ($request->expectsJson() || $request->is('api/*')) {
            return response()->json([
                'error' => 'Quarantined',
                'message' => $message,
                'ip' => $ip,
            ], $status);
        }

        return response(
            sprintf(
                '<!DOCTYPE html><html><head><title>429 Quarantined</title></head><body style="font-family:sans-serif;text-align:center;padding:50px;"><h1>Access Quarantined</h1><p>%s</p><small>IP: %s</small></body></html>',
                htmlspecialchars($message, ENT_QUOTES, 'UTF-8'),
                htmlspecialchars($ip, ENT_QUOTES, 'UTF-8')
            ),
            $status,
            ['Content-Type' => 'text/html; charset=UTF-8']
        );
    }

    /**
     * Build appropriate blocked HTTP response.
     */
    public function buildBlockedResponse(Request $request, SecurityThreat $threat): Response|JsonResponse
    {
        $status = (int) config('security-defense.middleware.payload_scanner.response_status', 403);
        $message = (string) config(
            'security-defense.middleware.payload_scanner.response_message',
            'Suspicious request payload detected and blocked.'
        );

        if ($request->expectsJson() || $request->is('api/*')) {
            return response()->json([
                'error' => 'Forbidden',
                'message' => $message,
                'threat_id' => substr($threat->fingerprint, 0, 16),
            ], $status);
        }

        return response(
            sprintf(
                '<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body style="font-family:sans-serif;text-align:center;padding:50px;"><h1>403 Forbidden</h1><p>%s</p><small>Reference ID: %s</small></body></html>',
                htmlspecialchars($message, ENT_QUOTES, 'UTF-8'),
                htmlspecialchars(substr($threat->fingerprint, 0, 16), ENT_QUOTES, 'UTF-8')
            ),
            $status,
            ['Content-Type' => 'text/html; charset=UTF-8']
        );
    }
}