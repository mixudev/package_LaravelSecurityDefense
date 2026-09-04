@props([
    'appName' => 'Laravel Application',
    'appEnv' => 'production',
])

<tr>
    <td class="email-header" style="padding: 20px 28px; border-bottom: 1px solid #e4e4e7; background-color: #ffffff;">
        <table width="100%" cellspacing="0" cellpadding="0" border="0">
            <tr>
                <td align="left" valign="middle">
                    <span style="font-size: 11px; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase; color: #71717a;" class="email-text-muted">
                        SECURITY DEFENSE SIEM
                    </span>
                    <div style="font-size: 16px; font-weight: 700; color: #09090b; margin-top: 2px;" class="email-text-title">
                        {{ $appName }}
                    </div>
                </td>
                <td align="right" valign="middle">
                    <span style="display: inline-block; padding: 3px 8px; font-size: 11px; font-weight: 600; text-transform: uppercase; border-radius: 4px; background-color: #f4f4f5; color: #3f3f46; border: 1px solid #e4e4e7; font-family: monospace;" class="email-code-bg">
                        {{ strtoupper($appEnv) }}
                    </span>
                </td>
            </tr>
        </table>
    </td>
</tr>
