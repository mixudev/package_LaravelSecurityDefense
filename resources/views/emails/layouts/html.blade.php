<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <title>@yield('title', 'Security Alert')</title>
    <style>
        /* Email client resets */
        body, table, td, a { -webkit-text-size-adjust: 100%; -ms-text-size-adjust: 100%; }
        table, td { mso-table-lspace: 0pt; mso-table-rspace: 0pt; }
        img { -ms-interpolation-mode: bicubic; border: 0; outline: none; text-decoration: none; }
        body { margin: 0; padding: 0; width: 100% !important; height: 100% !important; }

        /* Dark Mode Automatic Adaptation */
        @media (prefers-color-scheme: dark) {
            .email-bg { background-color: #09090b !important; }
            .email-card { background-color: #18181b !important; border-color: #27272a !important; }
            .email-header { background-color: #18181b !important; border-color: #27272a !important; }
            .email-text-title { color: #fafafa !important; }
            .email-text-main { color: #f4f4f5 !important; }
            .email-text-muted { color: #a1a1aa !important; }
            .email-border { border-color: #27272a !important; }
            .email-table-bg { background-color: #18181b !important; }
            .email-code-bg { background-color: #09090b !important; border-color: #27272a !important; color: #e4e4e7 !important; }
            .email-footer { border-color: #27272a !important; color: #71717a !important; }
        }
    </style>
</head>
<body class="email-bg" style="margin: 0; padding: 0; background-color: #f4f4f5; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; -webkit-font-smoothing: antialiased;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" class="email-bg" style="background-color: #f4f4f5; width: 100%; padding: 40px 16px;">
        <tr>
            <td align="center">
                <!-- Email Container Card -->
                <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" class="email-card" style="max-width: 580px; width: 100%; background-color: #ffffff; border: 1px solid #e4e4e7; border-radius: 8px; overflow: hidden;">
                    <!-- Email Header -->
                    @include('security-defense::emails.components.header', [
                        'appName' => $appName ?? config('app.name', 'Laravel Application'),
                        'appEnv' => $appEnv ?? app()->environment(),
                    ])

                    <!-- Main Content Body -->
                    <tr>
                        <td style="padding: 24px 28px;">
                            @yield('content')
                        </td>
                    </tr>

                    <!-- Email Footer -->
                    @include('security-defense::emails.components.footer')
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
