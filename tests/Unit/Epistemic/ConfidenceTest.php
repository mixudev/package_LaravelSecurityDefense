<?php
declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Unit\Epistemic;

use InvalidArgumentException;
use Mixudev\SecurityDefense\Epistemic\ValueObjects\Confidence;
use PHPUnit\Framework\TestCase;

class ConfidenceTest extends TestCase
{
    public function test_valid(): void
    {
        $this->assertEqualsWithDelta(0.75, Confidence::from(0.75)->value, 0.000001);
    }

    public function test_rejects_negative(): void
    {
        $this->expectException(InvalidArgumentException::class);
        Confidence::from(-0.1);
    }

    public function test_rejects_above_one(): void
    {
        $this->expectException(InvalidArgumentException::class);
        Confidence::from(1.001);
    }

    public function test_rejects_nan(): void
    {
        $this->expectException(InvalidArgumentException::class);
        Confidence::from(NAN);
    }

    public function test_rejects_inf(): void
    {
        $this->expectException(InvalidArgumentException::class);
        Confidence::from(INF);
    }

    public function test_combined(): void
    {
        $a = Confidence::from(0.9);
        $b = Confidence::from(0.4);
        $expected = sqrt(0.9 * 0.4);
        $this->assertEqualsWithDelta($expected, $a->combined($b)->value, 0.000001);
    }

    public function test_weakened_floor_zero(): void
    {
        $c = Confidence::from(0.1)->weakened(0.5);
        $this->assertEquals(0.0, $c->value);
    }

    public function test_strengthened_cap_one(): void
    {
        $c = Confidence::from(0.9)->strengthened(0.5);
        $this->assertEquals(1.0, $c->value);
    }
}
