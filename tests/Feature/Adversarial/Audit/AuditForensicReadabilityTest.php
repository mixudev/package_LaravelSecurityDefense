<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature\Adversarial\Audit;

use PHPUnit\Framework\Attributes\DataProvider;
use Mixudev\SecurityDefense\Support\Sanitizer;
use Mixudev\SecurityDefense\Tests\TestCase;

class AuditForensicReadabilityTest extends TestCase
{
    #[DataProvider('comparisonProvider')]
    public function test_numeric_comparisons_survive_defanging(string $expression): void
    {
        $clean = Sanitizer::cleanString($expression);
        $this->assertSame($expression, $clean);
    }

    #[DataProvider('comparisonProvider')]
    public function test_numeric_comparisons_keep_both_operands(string $expression): void
    {
        $clean = Sanitizer::cleanString($expression);
        $this->assertStringContainsString('<', $clean);
        if (str_contains($expression, '>')) {
            $this->assertStringContainsString('>', $clean);
        }
        // No tag-shaped bracketing may be introduced into forensic text.
        $this->assertDoesNotMatchRegularExpression('/\[[a-zA-Z][a-zA-Z0-9]*[ \]]/', $clean);
    }

    #[DataProvider('comparisonProvider')]
    public function test_cleaning_is_additive_for_forensic_text(string $expression): void
    {
        $clean = Sanitizer::clean(['evidence' => $expression]);
        $this->assertSame($expression, $clean['evidence']);
    }

    /** @return array<string,array{0:string}> */
    public static function comparisonProvider(): array
    {
        return [
            'age range' => ['age<30 and age>18'], 'price range' => ['price<100 and price>10'],
            'dates' => ['year<2026 and year>2020'], 'scores' => ['score>=80 and score<=100'],
            'sql prose' => ['items<30 and items>18'], 'negative' => ['temperature<-5 and temperature>-20'],
            'decimal' => ['ratio<1.5 and ratio>0.25'], 'currency' => ['cost<99.99 and cost>49.99'],
            'ids' => ['id<100000 and id>100'], 'count' => ['count<12 and count>0'],
            'spaces' => ['left < right and right > center'],
            'unicode' => ['width<宽度 and width>0'], 'mixed' => ['age < 30 AND age > 18'],
            'brackets' => ['x<10 > 2'], 'range comma' => ['1<value and value<9'],
            'time' => ['hour<23 and hour>0'], 'version' => ['version<3.0 and version>2.0'],
            'length' => ['length<255 and length>1'], 'quantity' => ['quantity<1000 and quantity>1'],
        ];
    }
}
