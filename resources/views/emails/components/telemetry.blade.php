@props([
    'data' => [],
    'title' => 'Sanitized Telemetry & Indicators',
])

@if(!empty($data))
    <div style="margin-top: 24px;">
        <div class="email-text-muted" style="font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; color: #71717a; margin-bottom: 8px;">
            {{ $title }}
        </div>
        <div class="email-code-bg" style="background-color: #f4f4f5; border: 1px solid #e4e4e7; border-radius: 6px; padding: 12px 14px; overflow-x: auto;">
            <pre style="margin: 0; font-family: 'JetBrains Mono', Consolas, Monaco, monospace; font-size: 11px; line-height: 1.5; color: #18181b; white-space: pre-wrap; word-break: break-all;">{{ json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) }}</pre>
        </div>
    </div>
@endif
