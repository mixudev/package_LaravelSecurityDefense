<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Dashboard Authorization Code</title>
</head>
<body style="margin: 0; padding: 32px 16px; background-color: #0c0c0e; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #e4e4e7;">
    <div style="max-width: 440px; margin: 0 auto; background: #121214; border: 1px solid #27272a; border-radius: 12px; padding: 32px;">
        <div style="font-size: 11px; text-transform: uppercase; letter-spacing: 0.1em; color: #a1a1aa; margin-bottom: 8px;">
            Security Defense
        </div>
        <h1 style="font-size: 18px; font-weight: 600; color: #fafafa; margin: 0 0 8px 0;">
            Authorization Code
        </h1>
        <p style="font-size: 13px; line-height: 1.5; color: #a1a1aa; margin: 0 0 24px 0;">
            Use the one-time code below to verify dashboard access from this environment. Valid for {{ $ttlMinutes }} minute(s).
        </p>

        <div style="background: #1c1c1f; border: 1px solid #3f3f46; border-radius: 8px; padding: 16px; text-align: center; margin-bottom: 24px;">
            <div style="font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 28px; font-weight: 700; letter-spacing: 0.35em; color: #34d399;">
                {{ $code }}
            </div>
        </div>

        <p style="font-size: 11px; line-height: 1.5; color: #71717a; margin: 0;">
            If you did not initiate this request, someone on your network may be attempting to access the security console. The code expires automatically and cannot be used after {{ $ttlMinutes }} minute(s).
        </p>
    </div>
</body>
</html>
