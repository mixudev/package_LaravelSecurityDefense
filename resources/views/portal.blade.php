<!DOCTYPE html>
<html lang="en" class="h-full">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure Entry</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            min-height: 100vh; display: flex; align-items: center; justify-content: center;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0c0c0e; color: #e4e4e7; padding: 1rem;
        }
        .card {
            width: 100%; max-width: 24rem; background: #121214; border: 1px solid #27272a;
            border-radius: 12px; padding: 2rem; text-align: center;
            box-shadow: 0 10px 30px rgba(0,0,0,0.35);
        }
        .badge {
            width: 4rem; height: 4rem; margin: 0 auto 1.25rem; border-radius: 9999px;
            display: flex; align-items: center; justify-content: center;
            background: rgba(16,185,129,0.12); border: 1px solid rgba(16,185,129,0.35);
        }
        h1 { font-size: 1.25rem; font-weight: 600; color: #fafafa; margin-bottom: 0.5rem; }
        p { font-size: 0.875rem; line-height: 1.6; color: #a1a1aa; margin-bottom: 1.5rem; }
        form { margin-bottom: 1.25rem; }
        button {
            width: 100%; display: inline-flex; align-items: center; justify-content: center; gap: 0.5rem;
            background: #10b981; color: #fff; border: none; border-radius: 8px;
            padding: 0.65rem 1rem; font-size: 0.875rem; font-weight: 500; cursor: pointer; transition: background 0.15s;
        }
        button:hover { background: #059669; }
        button svg { width: 1rem; height: 1rem; }
        .hint { font-size: 0.6875rem; color: #71717a; font-family: ui-monospace, monospace; }
    </style>
</head>
<body>
    <div class="card">
        <div class="badge">
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#34d399" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <path d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
            </svg>
        </div>
        <h1>Secure entry</h1>
        <p>This page is the verified gateway to the monitoring console. Access is restricted to authorized environments.</p>
        <form method="POST" action="{{ route('security-defense.portal.enter') }}">
            @csrf
            <button type="submit">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                    <path d="M13.5 4.5L21 12m0 0l-7.5 7.5M21 12H3" />
                </svg>
                Proceed to dashboard
            </button>
        </form>
        <p class="hint">Authorized access only</p>
    </div>
</body>
</html>