<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Rules;

use Mixudev\SecurityDefense\DTO\SecurityEvent;
use Mixudev\SecurityDefense\DTO\SecurityThreat;

/**
 * Detects impossible travel anomalies (e.g. login from two physically distant locations in an unrealistically short timeframe).
 */
class ImpossibleTravelRule extends AbstractDetectionRule
{
    public function identifier(): string
    {
        return 'impossible_travel';
    }

    public function name(): string
    {
        return 'Impossible Travel Detector';
    }

    public function evaluate(SecurityEvent $event): ?SecurityThreat
    {
        if (!$this->isEnabled()) {
            return null;
        }

        $monitoredEvents = (array) $this->getConfig('events', ['LoginSucceeded', 'NewDeviceLoginDetected']);
        if (!in_array($event->eventType, $monitoredEvents, true)) {
            return null;
        }

        if ($event->identifier === 'anonymous' || trim($event->identifier) === '') {
            return null;
        }

        $maxSpeed = (float) $this->getConfig('max_speed_kmh', 900.0);
        $window = (int) $this->getConfig('window', 3600);
        $severity = (string) $this->getConfig('severity', 'high');

        $currentLat = isset($event->metadata['latitude']) ? (float) $event->metadata['latitude'] : null;
        $currentLon = isset($event->metadata['longitude']) ? (float) $event->metadata['longitude'] : null;
        $currentCountry = isset($event->metadata['country']) ? (string) $event->metadata['country'] : null;

        $target = strtolower($event->identifier);
        $cacheKey = $this->getCacheKey('location:' . md5($target));

        $cache = $this->getCache();
        $now = time();

        /** @var array{ip: string, lat: float|null, lon: float|null, country: string|null, timestamp: int}|null $lastLocation */
        $lastLocation = $cache->get($cacheKey);

        // Update cache with latest location
        $cache->put($cacheKey, [
            'ip' => $event->ip,
            'lat' => $currentLat,
            'lon' => $currentLon,
            'country' => $currentCountry,
            'timestamp' => $now,
        ], $window);

        if (!$lastLocation || ($now - $lastLocation['timestamp']) > $window) {
            return null;
        }

        // Check if IP is identical (no travel)
        if ($lastLocation['ip'] === $event->ip) {
            return null;
        }

        $timeDiffSeconds = max(1, $now - $lastLocation['timestamp']);
        $timeDiffHours = $timeDiffSeconds / 3600;

        // Coordinate-based calculation if coordinates are present
        if (
            $currentLat !== null && $currentLon !== null &&
            $lastLocation['lat'] !== null && $lastLocation['lon'] !== null
        ) {
            $distanceKm = $this->calculateDistanceKm(
                $lastLocation['lat'],
                $lastLocation['lon'],
                $currentLat,
                $currentLon
            );

            $calculatedSpeed = $distanceKm / $timeDiffHours;

            if ($calculatedSpeed > $maxSpeed) {
                $fingerprint = hash('sha256', sprintf('impossible_travel:%s:%s:%s', $target, $lastLocation['ip'], $event->ip));

                return new SecurityThreat(
                    severity: $severity,
                    threatType: 'impossible_travel',
                    fingerprint: $fingerprint,
                    metadata: [
                        'identifier' => $target,
                        'previous_ip' => $lastLocation['ip'],
                        'current_ip' => $event->ip,
                        'distance_km' => round($distanceKm, 2),
                        'time_elapsed_seconds' => $timeDiffSeconds,
                        'calculated_speed_kmh' => round($calculatedSpeed, 2),
                        'max_allowed_speed_kmh' => $maxSpeed,
                        'previous_location' => ['lat' => $lastLocation['lat'], 'lon' => $lastLocation['lon']],
                        'current_location' => ['lat' => $currentLat, 'lon' => $currentLon],
                    ],
                    ruleIdentifier: $this->identifier()
                );
            }
        } elseif (
            $currentCountry !== null &&
            $lastLocation['country'] !== null &&
            strtolower($currentCountry) !== strtolower($lastLocation['country']) &&
            $timeDiffSeconds < 600 // Different country in under 10 minutes
        ) {
            // Country mismatch within 10 minutes without coordinates
            $fingerprint = hash('sha256', sprintf('impossible_travel:%s:%s:%s', $target, $lastLocation['country'], $currentCountry));

            return new SecurityThreat(
                severity: $severity,
                threatType: 'impossible_travel',
                fingerprint: $fingerprint,
                metadata: [
                    'identifier' => $target,
                    'previous_ip' => $lastLocation['ip'],
                    'current_ip' => $event->ip,
                    'previous_country' => $lastLocation['country'],
                    'current_country' => $currentCountry,
                    'time_elapsed_seconds' => $timeDiffSeconds,
                ],
                ruleIdentifier: $this->identifier()
            );
        }

        return null;
    }

    /**
     * Calculate great-circle distance between two points on a sphere (Haversine formula).
     */
    protected function calculateDistanceKm(float $lat1, float $lon1, float $lat2, float $lon2): float
    {
        $earthRadiusKm = 6371.0;

        $dLat = deg2rad($lat2 - $lat1);
        $dLon = deg2rad($lon2 - $lon1);

        $a = sin($dLat / 2) * sin($dLat / 2) +
            cos(deg2rad($lat1)) * cos(deg2rad($lat2)) *
            sin($dLon / 2) * sin($dLon / 2);

        $c = 2 * atan2(sqrt($a), sqrt(1 - $a));

        return $earthRadiusKm * $c;
    }
}
