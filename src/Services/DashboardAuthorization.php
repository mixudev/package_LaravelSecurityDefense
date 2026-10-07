<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Services;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Throwable;

/**
 * Server-side dashboard authorization. It never trusts role or permission data
 * supplied by the request; all decisions are derived from the authenticated user.
 */
final class DashboardAuthorization
{
    public function allows(Request $request, array $config): bool
    {
        // Fail-closed contract: malformed configuration (non-string modes,
        // illegal casts, etc.) must deny, never surface as an exception the
        // caller could accidentally turn into an allow or a 500.
        try {
            return $this->decide($request, $config);
        } catch (Throwable) {
            return false;
        }
    }

    private function decide(Request $request, array $config): bool
    {
        $user = $request->user();
        if ($user === null) {
            return false;
        }

        if (!(bool) ($config['enabled'] ?? false)) {
            return true;
        }

        $mode = array_key_exists('mode', $config) ? $config['mode'] : 'none';
        if (!is_string($mode)) {
            return false;
        }

        return match ($mode) {
            'none' => true,
            'gate', 'ability' => $this->allowsGate($user, $request, $config),
            'role' => $this->allowsRole($user, $config),
            'custom' => $this->allowsCustom($user, $request, $config),
            default => false,
        };
    }

    private function allowsGate(Authenticatable $user, Request $request, array $config): bool
    {
        $name = $config['name'] ?? $config['gate'] ?? $config['ability'] ?? null;
        if (!is_string($name) || $name === '') {
            return false;
        }

        try {
            return Gate::forUser($user)->check($name, [$request]);
        } catch (Throwable) {
            return false;
        }
    }

    private function allowsRole(Authenticatable $user, array $config): bool
    {
        $roles = array_values(array_filter((array) ($config['roles'] ?? []), 'is_string'));
        if ($roles === []) {
            return false;
        }

        $method = (string) ($config['role_method'] ?? 'hasAnyRole');
        try {
            if ($method === 'hasAnyRole' && method_exists($user, 'hasAnyRole')) {
                return (bool) $user->hasAnyRole($roles);
            }
            if ($method === 'hasRole' && method_exists($user, 'hasRole')) {
                foreach ($roles as $role) {
                    if ($user->hasRole($role)) {
                        return true;
                    }
                }
                return false;
            }

            // Supports simple custom User models without trusting request input.
            $attribute = (string) ($config['role_attribute'] ?? 'roles');
            $value = $user->{$attribute} ?? null;
            if ($value instanceof \Illuminate\Support\Collection) {
                $value = $value->all();
            }
            $owned = is_array($value) ? $value : (is_string($value) ? [$value] : []);
            $owned = array_map(static fn ($role): string => is_object($role)
                ? (string) ($role->name ?? $role->slug ?? '')
                : (string) $role, $owned);

            return array_intersect($roles, $owned) !== [];
        } catch (Throwable) {
            return false;
        }
    }

    private function allowsCustom(Authenticatable $user, Request $request, array $config): bool
    {
        $resolver = $config['resolver'] ?? null;
        if (!is_string($resolver) || $resolver === '') {
            return false;
        }

        try {
            $instance = app($resolver);
            // Only an explicit boolean true authorizes. Truthy non-boolean
            // results (strings, numbers, arrays) from a sloppy resolver must
            // never grant access.
            return is_callable($instance) && $instance($user, $request, $config) === true;
        } catch (Throwable) {
            return false;
        }
    }
}
