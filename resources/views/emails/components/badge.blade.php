@props([
    'severity' => 'low',
])

@php
    $sev = strtolower($severity);
    $config = match($sev) {
        'critical' => [
            'bg' => '#fef2f2',
            'color' => '#b91c1c',
            'border' => '#fecaca',
        ],
        'high' => [
            'bg' => '#fff7ed',
            'color' => '#c2410c',
            'border' => '#fed7aa',
        ],
        'medium' => [
            'bg' => '#fffbeb',
            'color' => '#b45309',
            'border' => '#fde68a',
        ],
        default => [
            'bg' => '#f4f4f5',
            'color' => '#3f3f46',
            'border' => '#e4e4e7',
        ],
    };
@endphp

<span style="display: inline-block; padding: 4px 10px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; border-radius: 4px; background-color: {{ $config['bg'] }}; color: {{ $config['color'] }}; border: 1px solid {{ $config['border'] }};">
    {{ strtoupper($severity) }}
</span>
