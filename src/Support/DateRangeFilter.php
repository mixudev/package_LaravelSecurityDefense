<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Support;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Http\Request;

/**
 * Resolves a global dashboard date-range filter (`range` + `from`/`to` inputs)
 * into a `[from, to]` Carbon pair, and applies it to an Eloquent builder.
 *
 * Presets: today, 7d, 30d, all. Custom range via `from`/`to` (YYYY-MM-DD).
 */
class DateRangeFilter
{
    public const PRESETS = ['today', '7d', '30d'];

    /**
     * Resolve the effective date range from the request.
     *
     * @return array{from: \Illuminate\Support\Carbon|null, to: \Illuminate\Support\Carbon|null, preset: string}
     */
    public static function resolve(Request $request): array
    {
        $preset = (string) $request->query('range', '30d');

        if (!in_array($preset, self::PRESETS, true)) {
            $preset = '30d';
        }

        if ($preset === 'today') {
            return ['from' => now()->startOfDay(), 'to' => now()->endOfDay(), 'preset' => 'today'];
        }

        if ($preset === '7d') {
            return ['from' => now()->subDays(6)->startOfDay(), 'to' => now()->endOfDay(), 'preset' => '7d'];
        }

        return ['from' => now()->subDays(29)->startOfDay(), 'to' => now()->endOfDay(), 'preset' => '30d'];
    }

    /**
     * Apply a resolved date range to an Eloquent query on a `created_at` column.
     *
     * @param  Builder<\Illuminate\Database\Eloquent\Model>  $query
     * @param  array{from: \Illuminate\Support\Carbon|null, to: \Illuminate\Support\Carbon|null}  $range
     */
    public static function apply(Builder $query, array $range): void
    {
        if ($range['from'] !== null) {
            $query->where('created_at', '>=', $range['from']);
        }

        if ($range['to'] !== null) {
            $query->where('created_at', '<=', $range['to']);
        }
    }
}