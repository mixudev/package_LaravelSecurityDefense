<!DOCTYPE html>
<html lang="id" class="h-full">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Portal Akses Dibatasi - Security Defense</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            min-height: 100vh; display: flex; align-items: center; justify-content: center;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0c0c0e; color: #e4e4e7; padding: 1.25rem;
        }
        .card {
            width: 100%; max-width: 25rem; background: #121214; border: 1px solid #27272a;
            border-radius: 12px; padding: 2rem; text-align: center;
            box-shadow: 0 12px 32px rgba(0,0,0,0.4);
        }
        .badge {
            width: 4rem; height: 4rem; margin: 0 auto 1.25rem; border-radius: 9999px;
            display: flex; align-items: center; justify-content: center;
            background: rgba(239,68,68,0.12); border: 1px solid rgba(239,68,68,0.35);
        }
        h1 { font-size: 1.25rem; font-weight: 600; color: #fafafa; margin-bottom: 0.35rem; }
        .subtitle { font-size: 0.75rem; color: #71717a; font-family: ui-monospace, monospace; margin-bottom: 1.25rem; letter-spacing: 0.05em; }
        .alert-box {
            background: #18181b; border: 1px solid #27272a; border-left: 3px solid #ef4444;
            border-radius: 8px; padding: 0.85rem 1rem; font-size: 0.8125rem; color: #d4d4d8;
            margin-bottom: 1.25rem; text-align: left; line-height: 1.5;
        }
        p { font-size: 0.85rem; line-height: 1.6; color: #a1a1aa; margin-bottom: 1.5rem; text-align: left; }
        .back {
            width: 100%; display: inline-flex; align-items: center; justify-content: center; gap: 0.5rem;
            background: #27272a; color: #e4e4e7; border: 1px solid #3f3f46; border-radius: 8px;
            padding: 0.65rem 1rem; font-size: 0.875rem; font-weight: 500; text-decoration: none;
            transition: background 0.15s, border-color 0.15s;
        }
        .back:hover { background: #3f3f46; color: #fff; }
    </style>
</head>
<body>
    <div class="card">
        <div class="badge">
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#f87171" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <path d="M12 9v4m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
            </svg>
        </div>
        <h1>Portal Akses Dibatasi</h1>
        <div class="subtitle">Security Defense &bull; 403 Forbidden.</div>
        <div class="alert-box">
            <strong>Peringatan Keamanan:</strong> Permintaan ke gerbang monitoring ditolak oleh kebijakan otorisasi jaringan.
        </div>
        <p>Akses dibatasi hanya untuk alamat IP dan lingkungan yang telah terdaftar. Pastikan IP Anda masuk dalam daftar izin di konfigurasi atau hubungi administrator sistem.</p>
        <a class="back" href="{{ url('/') }}">&larr; Kembali ke Halaman Utama</a>
    </div>
</body>
</html>