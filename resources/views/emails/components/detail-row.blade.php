@props([
    'label',
    'value',
    'isMono' => false,
    'isLast' => false,
])

<tr>
    <td class="email-text-muted email-border" style="padding: 10px 14px; {{ $isLast ? '' : 'border-bottom: 1px solid #e4e4e7;' }} font-size: 13px; color: #71717a; width: 35%; font-weight: 500;">
        {{ $label }}
    </td>
    <td class="email-text-main email-border" style="padding: 10px 14px; {{ $isLast ? '' : 'border-bottom: 1px solid #e4e4e7;' }} font-size: 13px; color: #09090b; font-weight: 600; {{ $isMono ? "font-family: 'JetBrains Mono', Consolas, Monaco, monospace; font-size: 12px;" : '' }}">
        {{ $value }}
    </td>
</tr>
