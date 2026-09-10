<?php
declare(strict_types=1);

namespace Mixudev\SecurityDefense\Epistemic\ValueObjects;

use InvalidArgumentException;

final class RiskScore
{
    private function __construct(public readonly float $value) {}

    public static function from(float $value): self
    {
        if (!is_finite($value) || $value < 0.0 || $value > 1.0) {
            throw new InvalidArgumentException(
                "RiskScore must be in [0.0, 1.0], got: {$value}"
            );
        }
        return new self(round($value, 6));
    }

    public static function zero(): self { return new self(0.0); }
    public static function max(): self  { return new self(1.0); }

    public function isHigherThan(self $other): bool { return $this->value > $other->value; }

    public function decayed(float $factor): self
    {
        return self::from(max(0.0, min(1.0, $this->value * $factor)));
    }

    public function toFloat(): float { return $this->value; }
}
