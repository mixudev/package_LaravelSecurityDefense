<?php
declare(strict_types=1);

namespace Mixudev\SecurityDefense\Epistemic\ValueObjects;

use InvalidArgumentException;

final class Confidence
{
    private function __construct(public readonly float $value) {}

    public static function from(float $value): self
    {
        if (!is_finite($value) || $value < 0.0 || $value > 1.0) {
            throw new InvalidArgumentException(
                "Confidence must be in [0.0, 1.0], got: {$value}"
            );
        }
        return new self(round($value, 6));
    }

    public static function zero(): self { return new self(0.0); }
    public static function max(): self  { return new self(1.0); }

    public function combined(self $other): self
    {
        return self::from(sqrt($this->value * $other->value));
    }

    public function weakened(float $delta): self
    {
        return self::from(max(0.0, $this->value - abs($delta)));
    }

    public function strengthened(float $delta): self
    {
        return self::from(min(1.0, $this->value + abs($delta)));
    }

    public function toFloat(): float { return $this->value; }
}
