<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Services;

/**
 * Strict exact-IP and IPv4/IPv6 CIDR matching for dashboard access control.
 * No DNS lookups, no regex, no proxy-header parsing.
 */
final class DashboardAccessPolicy
{
    /** @var array<string, string> Validated exact IPs (both normalize to dotted/colon form). */
    private readonly array $allowedIps;

    /** @var array{cidr: string, length: int, networkBytes: string}[] */
    private readonly array $allowedCidrs;

    public function __construct(array $allowedIps, array $allowedCidrs)
    {
        $this->allowedIps = $this->normalizeExactIps($allowedIps);
        $this->allowedCidrs = $this->parseCidrs($allowedCidrs);
    }

    public function allows(string $ip): bool
    {
        $packed = @inet_pton($ip);

        if ($packed === false) {
            return false;
        }

        $normalized = inet_ntop($packed);

        if (isset($this->allowedIps[$normalized])) {
            return true;
        }

        return $this->matchesAnyCidr($normalized);
    }

    /** @return array<string, string> */
    private function normalizeExactIps(array $ips): array
    {
        $map = [];

        foreach ($ips as $ip) {
            if (! is_string($ip)) {
                continue;
            }

            $packed = @inet_pton($ip);

            if ($packed !== false) {
                $normalized = inet_ntop($packed);
                $map[$normalized] = $normalized;
            }
        }

        return $map;
    }

    /**
     * @return array{cidr: string, length: int, networkBytes: string}[]
     */
    private function parseCidrs(array $cidrs): array
    {
        $parsed = [];

        foreach ($cidrs as $cidr) {
            if (! is_string($cidr) || ! preg_match('#^([^/]+)/(\d+)$#', $cidr, $m)) {
                continue;
            }

            $prefix = $m[1];
            $length = (int) $m[2];
            $networkAddr = @inet_pton($prefix);

            if ($networkAddr === false) {
                continue;
            }

            $addrLength = strlen($networkAddr);
            $bits = $addrLength * 8;

            // Reject prefix length that exceeds the address bit width or is negative
            if ($length < 0 || $length > $bits) {
                continue;
            }

            // Normalize network to the masked version so host bits don't cause false negatives.
            if ($length > 0) {
                $maskBytes = str_repeat("\xff", intdiv($length, 8));

                $remainderBits = $length % 8;

                if ($remainderBits > 0) {
                    $maskBytes .= chr((0xff << (8 - $remainderBits)) & 0xff);
                }

                $pad = str_repeat("\0", $bits / 8 - strlen($maskBytes));
                $networkAddr = $networkAddr & ($maskBytes . $pad);
            }

            $parsed[] = [
                'cidr' => $cidr,
                'length' => $length,
                'networkBytes' => $networkAddr,
            ];
        }

        return $parsed;
    }

    private function matchesAnyCidr(string $normalized): bool
    {
        $addr = @inet_pton($normalized);

        if ($addr === false) {
            return false;
        }

        foreach ($this->allowedCidrs as $entry) {
            $addrLength = strlen($addr);

            if ($addrLength !== strlen($entry['networkBytes'])) {
                continue;
            }

            if ($entry['length'] === 0) {
                return true;
            }

            $fullMaskBits = $entry['length'];
            $maskBytes = str_repeat("\xff", intdiv($fullMaskBits, 8));
            $remainderBits = $fullMaskBits % 8;

            if ($remainderBits > 0) {
                $maskBytes .= chr((0xff << (8 - $remainderBits)) & 0xff);
            }

            $pad = str_repeat("\0", $addrLength - strlen($maskBytes));
            $mask = $maskBytes . $pad;

            if (($addr & $mask) === $entry['networkBytes']) {
                return true;
            }
        }

        return false;
    }
}