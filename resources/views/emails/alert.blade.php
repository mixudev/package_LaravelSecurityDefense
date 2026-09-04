@extends('security-defense::emails.layouts.html')

@section('title', strtoupper($alert->severity ?? 'security') . ' Security Alert')

@section('content')
    <!-- Threat Summary -->
    <table width="100%" role="presentation" cellspacing="0" cellpadding="0" border="0">
        <tr>
            <td style="padding: 0 0 18px 0;">
                <table width="100%" role="presentation" cellspacing="0" cellpadding="0" border="0">
                    <tr>
                        <td valign="middle">
                            <div class="email-text-muted" style="font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; color: #71717a;">
                                Threat Detected
                            </div>
                            <div class="email-text-title" style="font-size: 20px; font-weight: 700; color: #09090b; margin-top: 2px; text-transform: capitalize;">
                                {{ str_replace('_', ' ', $alert->threat_type) }}
                            </div>
                            <div class="email-text-muted" style="font-size: 12px; color: #71717a; margin-top: 2px;">
                                Triggered by rule: <code style="font-family: 'JetBrains Mono', Consolas, Monaco, monospace; font-size: 11px; color: #18181b; background-color: #f4f4f5; padding: 1px 5px; border-radius: 3px; border: 1px solid #e4e4e7;">{{ $alert->rule_identifier ?? 'N/A' }}</code>
                            </div>
                        </td>
                        <td align="right" valign="middle" style="padding-left: 16px;">
                            @include('security-defense::emails.components.badge', ['severity' => $alert->severity])
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>

    <!-- Details -->
    <table width="100%" class="email-table-bg" role="presentation" cellspacing="0" cellpadding="0" border="0" style="width: 100%; background-color: #ffffff; border: 1px solid #e4e4e7; border-radius: 6px; overflow: hidden;">
        @include('security-defense::emails.components.detail-row', ['label' => 'Alert ID', 'value' => '#' . $alert->id])
        @include('security-defense::emails.components.detail-row', ['label' => 'Fingerprint', 'value' => $alert->fingerprint, 'isMono' => true])
        @include('security-defense::emails.components.detail-row', ['label' => 'Detected At', 'value' => $alert->created_at ? $alert->created_at->toIso8601String() : now()->toIso8601String()])
        @include('security-defense::emails.components.detail-row', ['label' => 'Status', 'value' => strtoupper($alert->status), 'isLast' => true])
    </table>

    <!-- Sanitized Telemetry -->
    @include('security-defense::emails.components.telemetry', ['data' => $metadata ?? [], 'title' => 'Sanitized Telemetry & Indicators'])
@endsection
