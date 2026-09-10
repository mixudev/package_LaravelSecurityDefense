<?php
declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Unit\Epistemic;

use InvalidArgumentException;
use Mixudev\SecurityDefense\Epistemic\ValueObjects\RiskScore;
use PHPUnit\Framework\TestCase;

class RiskScoreTest extends TestCase
{
    public function test_valid(): void
    {
        $this->assertEqualsWithDelta(0.91, RiskScore::from(0.91)->value, 0.000001);
    }

    public function test_zero(): void
    {
        $this->assertEquals(0.0, RiskScore::zero()->value);
    }

    public function test_max(): void
    {
        $this->assertEquals(1.0, RiskScore::max()->value);
    }

    public function test_rejects_negative(): void
    {
        $this->expectException(InvalidArgumentException::class);
        RiskScore::from(-0.1);
    }

    public function test_rejects_above_one(): void
    {
        $this->expectException(InvalidArgumentException::class);
        RiskScore::from(1.001);
    }

    public function test_rejects_nan(): void
    {
        $this->expectException(InvalidArgumentException::class);
        RiskScore::from(NAN);
    }

    public function test_rejects_infinity(): void
    {
        $this->expectException(InvalidArgumentException::class);
        RiskScore::from(INF);
    }

    public function test_decay(): void
    {
        $s = RiskScore::from(1.0)->decayed(0.95);
        $this->assertEqualsWithDelta(0.95, $s->value, 0.000001);
    }

    public function test_is_higher_than(): void
    {
        $a = RiskScore::from(0.8);
        $b = RiskScore::from(0.5);
        $this->assertTrue($a->isHigherThan($b));
        $this->assertFalse($b->isHigherThan($a));
    }
}
