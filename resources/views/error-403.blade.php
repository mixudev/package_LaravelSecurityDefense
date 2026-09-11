<!DOCTYPE html>
<html lang="id" class="h-full">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>403 Forbidden - Security Defense</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            min-height: 100vh; display: flex; align-items: center; justify-content: center;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0c0c0e; color: #e4e4e7; padding: 1.5rem;
        }
        .card {
            width: 100%; max-width: 28rem; background: #121214; border: 1px solid #27272a;
            border-radius: 14px; padding: 2.25rem; box-shadow: 0 20px 40px rgba(0,0,0,0.5);
            text-align: center;
        }
        .badge {
            width: 4rem; height: 4rem; margin: 0 auto 1.25rem; border-radius: 9999px;
            display: flex; align-items: center; justify-content: center;
            background: rgba(239,68,68,0.12); border: 1px solid rgba(239,68,68,0.4);
        }
        h1 { font-size: 1.35rem; font-weight: 600; color: #f87171; margin-bottom: 0.5rem; }
        .subtitle { font-size: 0.8125rem; color: #71717a; font-family: ui-monospace, monospace; margin-bottom: 1.25rem; }
        p { font-size: 0.875rem; line-height: 1.65; color: #a1a1aa; margin-bottom: 1.5rem; text-align: left; }
        .alert-box {
            background: #18181b; border: 1px solid #27272a; border-left: 3px solid #f87171;
            border-radius: 8px; padding: 0.875rem 1rem; font-size: 0.8125rem; color: #d4d4d8;
            margin-bottom: 1.75rem; text-align: left; line-height: 1.5;
        }
        .back {
            display: inline-flex; align-items: center; gap: 0.5rem;
            background: #27272a; color: #e4e4e7; border-radius: 8px;
            padding: 0.6rem 1.25rem; font-size: 0.875rem; font-weight: 500;
            text-decoration: none; transition: background 0.15s;
        }
        .back:hover { background: #3f3f46; }
    </style>
</head>
<body>
    <div class="card">
        <div class="badge">
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#f87171" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <path d="M12 9v4m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
            </svg>
        </div>
        <h1>Akses Ditolak</h1>
        <div class="subtitle">403 Forbidden.</div>
        <div class="alert-box">
            <strong>Peringatan Keamanan:</strong> Permintaan Anda menuju portal ini ditolak karena tidak memenuhi kebijakan otorisasi atau batasan jaringan yang ditetapkan.
        </div>
        <p>Akses ke konsol pemantauan Security Defense dibatasi secara ketat hanya untuk lingkungan dan operator sah yang telah terotentikasi. Hubungi administrator sistem jika Anda membutuhkan izin akses.</p>
        <a class="back" href="{{ url('/') }}">&larr; Kembali ke Halaman Utama</a>
    </div>
</body>
</html>