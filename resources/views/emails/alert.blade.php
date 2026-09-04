<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ strtoupper($alert->severity) }} Security Alert</title>
</head>
<body style="margin: 0; padding: 0; background-color: #0b0f19; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #e2e8f0;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color: #0b0f19; padding: 32px 16px;">
        <tr>
            <td align="center">
                <table role="presentation" width="100%" style="max-width: 620px; background-color: #111827; border: 1px solid #1f2937; border-radius: 12px; overflow: hidden; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5);">
                    <!-- Header -->
                    <tr>
                        <td style="padding: 24px 28px; background-color: #0f172a; border-bottom: 1px solid #1e293b;">
                            <table width="100%" cellspacing="0" cellpadding="0">
                                <tr>
                                    <td>
                                        <div style="font-size: 11px; font-weight: 700; letter-spacing: 0.1em; text-transform: uppercase; color: #38bdf8;">
                                            SECURITY DEFENSE SIEM
                                        </div>
                                        <div style="font-size: 18px; font-weight: 700; color: #f8fafc; margin-top: 4px;">
                                            {{ $appName }} &bull; <span style="color: #94a3b8; font-weight: 500; font-size: 14px;">{{ strtoupper($appEnv) }}</span>
                                        </div>
                                    </td>
                                    <td align="right">
                                        @php
                                            $severity = strtolower($alert->severity);
                                            $bg = match($severity) {
                                                'critical' => '#ef4444',
                                                'high' => '#f97316',
                                                'medium' => '#eab308',
                                                default => '#3b82f6',
                                            };
                                            $color = match($severity) {
                                                'medium' => '#1e293b',
                                                default => '#ffffff',
                                            };
                                        @endphp
                                        <span style="display: inline-block; padding: 6px 14px; background-color: {{ $bg }}; color: {{ $color }}; font-size: 12px; font-weight: 800; text-transform: uppercase; border-radius: 9999px; letter-spacing: 0.05em;">
                                            {{ strtoupper($alert->severity) }}
                                        </span>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>

                    <!-- Threat Summary Banner -->
                    <tr>
                        <td style="padding: 24px 28px;">
                            <div style="font-size: 13px; color: #94a3b8; text-transform: uppercase; font-weight: 600; letter-spacing: 0.05em;">
                                Threat Detected
                            </div>
                            <div style="font-size: 22px; font-weight: 700; color: #f1f5f9; margin-top: 4px; text-transform: capitalize;">
                                {{ str_replace('_', ' ', $alert->threat_type) }}
                            </div>
                            <div style="font-size: 13px; color: #64748b; margin-top: 6px;">
                                Triggered by rule: <code style="color: #38bdf8; background-color: #1e293b; padding: 2px 6px; border-radius: 4px; font-family: monospace;">{{ $alert->rule_identifier ?? 'N/A' }}</code>
                            </div>
                        </td>
                    </tr>

                    <!-- Details Table -->
                    <tr>
                        <td style="padding: 0 28px 24px 28px;">
                            <table width="100%" cellspacing="0" cellpadding="0" style="background-color: #0a0f1d; border: 1px solid #1e293b; border-radius: 8px; font-size: 13px;">
                                <tr>
                                    <td style="padding: 10px 14px; border-bottom: 1px solid #1e293b; color: #94a3b8; width: 35%;">Alert ID</td>
                                    <td style="padding: 10px 14px; border-bottom: 1px solid #1e293b; color: #f8fafc; font-weight: 600;">#{{ $alert->id }}</td>
                                </tr>
                                <tr>
                                    <td style="padding: 10px 14px; border-bottom: 1px solid #1e293b; color: #94a3b8;">Fingerprint</td>
                                    <td style="padding: 10px 14px; border-bottom: 1px solid #1e293b; color: #e2e8f0; font-family: monospace;">{{ $alert->fingerprint }}</td>
                                </tr>
                                <tr>
                                    <td style="padding: 10px 14px; border-bottom: 1px solid #1e293b; color: #94a3b8;">Detected At</td>
                                    <td style="padding: 10px 14px; border-bottom: 1px solid #1e293b; color: #f8fafc;">{{ $alert->created_at ? $alert->created_at->toIso8601String() : now()->toIso8601String() }}</td>
                                </tr>
                                <tr>
                                    <td style="padding: 10px 14px; color: #94a3b8;">Status</td>
                                    <td style="padding: 10px 14px; color: #22c55e; font-weight: 600; text-transform: uppercase;">{{ $alert->status }}</td>
                                </tr>
                            </table>
                        </td>
                    </tr>

                    <!-- Metadata Details -->
                    @if(!empty($metadata))
                    <tr>
                        <td style="padding: 0 28px 28px 28px;">
                            <div style="font-size: 13px; font-weight: 600; color: #94a3b8; margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.05em;">
                                Sanitized Telemetry & Indicators
                            </div>
                            <div style="background-color: #050811; border: 1px solid #1e293b; border-radius: 8px; padding: 14px; overflow-x: auto;">
                                <pre style="margin: 0; font-family: monospace; font-size: 12px; color: #a5b4fc; white-space: pre-wrap; word-break: break-all;">{{ json_encode($metadata, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) }}</pre>
                            </div>
                        </td>
                    </tr>
                    @endif

                    <!-- Footer -->
                    <tr>
                        <td style="padding: 18px 28px; background-color: #0a0f1d; border-top: 1px solid #1e293b; font-size: 12px; color: #64748b; text-align: center;">
                            Automated notification from <strong style="color: #94a3b8;">Laravel Security Defense</strong>. Protected against ReDoS, credential exposure, and alert floods.
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
