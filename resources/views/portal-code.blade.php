<!DOCTYPE html>
<html lang="en" class="h-full">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authorization Code</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 1rem; background: #0c0c0e; color: #e4e4e7; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        .card { width: 100%; max-width: 24rem; padding: 2rem; text-align: center; background: #121214; border: 1px solid #27272a; border-radius: 12px; box-shadow: 0 10px 30px rgba(0,0,0,.35); }
        .badge { width: 4rem; height: 4rem; margin: 0 auto 1.25rem; display: flex; align-items: center; justify-content: center; border-radius: 9999px; background: rgba(234,179,8,.12); border: 1px solid rgba(234,179,8,.35); }
        h1 { margin-bottom: .5rem; color: #fafafa; font-size: 1.25rem; font-weight: 600; }
        p { margin-bottom: 1.25rem; color: #a1a1aa; font-size: .875rem; line-height: 1.6; }
        .error { margin-bottom: 1rem; padding: .5rem .75rem; color: #fca5a5; background: rgba(239,68,68,.1); border: 1px solid rgba(239,68,68,.3); border-radius: 6px; font-size: .8125rem; }
        input { width: 100%; margin-bottom: 1rem; padding: .65rem .75rem; color: #fafafa; background: #1c1c1f; border: 1px solid #3f3f46; border-radius: 8px; font-family: ui-monospace, monospace; font-size: 1.25rem; letter-spacing: .3em; text-align: center; text-transform: uppercase; }
        input:focus { outline: 2px solid #eab308; border-color: #eab308; }
        button { width: 100%; padding: .65rem 1rem; color: #18181b; background: #eab308; border: 0; border-radius: 8px; font-size: .875rem; font-weight: 600; cursor: pointer; }
        button:hover { background: #ca8a04; }
        .back { display: block; margin-top: 1rem; color: #71717a; font-size: .75rem; text-decoration: none; }
        .back:hover { color: #a1a1aa; }
    </style>
</head>
<body>
    <div class="card">
        <div class="badge">
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#eab308" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <path d="M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z" />
            </svg>
        </div>
        <h1>Authorization Code</h1>
        <p>Enter the 8-character code sent to your configured channel.</p>

        @if (session('otp_error'))
            <div class="error">{{ session('otp_error') }}</div>
        @endif

        <form method="POST" action="{{ route('security-defense.portal.verify-otp') }}">
            @csrf
            <input type="text" name="otp_code" maxlength="8" autocomplete="one-time-code" placeholder="XXXXXXXX" autofocus inputmode="text" pattern="[A-Za-z0-9]{8}" required>
            <button type="submit">Verify</button>
        </form>

        <a href="{{ route('security-defense.portal.index') }}" class="back">Request a new code</a>
    </div>
</body>
</html>
