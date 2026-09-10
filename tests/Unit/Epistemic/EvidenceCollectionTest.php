<?php
declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Unit\Epistemic;

use DateTimeImmutable;
use Mixudev\SecurityDefense\Epistemic\Evidence\Evidence;
use Mixudev\SecurityDefense\Epistemic\Evidence\EvidenceCollection;
use Mixudev\SecurityDefense\Epistemic\ValueObjects\Confidence;
use Mixudev\SecurityDefense\Epistemic\ValueObjects\EvidenceType;
use PHPUnit\Framework\TestCase;

class EvidenceCollectionTest extends TestCase
{
    private function make(EvidenceType $type, string $id): Evidence
    {
        return new Evidence($type, 'test', new DateTimeImmutable(), Confidence::from(0.8), [], $id);
    }

    public function test_dedup_same_id(): void
    {
        $col = new EvidenceCollection();
        $e   = $this->make(EvidenceType::LOGIN_FAILED, 'abc');
        $col->add($e);
        $col->add($e);
        $this->assertEquals(1, $col->count());
    }

    public function test_supporting_excludes_trusted_device(): void
    {
        $col = new EvidenceCollection();
        $col->add($this->make(EvidenceType::LOGIN_FAILED, 'a'));
        $col->add($this->make(EvidenceType::TRUSTED_DEVICE, 'b'));
        $this->assertCount(1, $col->supporting());
        $this->assertEquals('login_failed', $col->supporting()[0]->type->value);
    }

    public function test_contradicting_only_trusted_types(): void
    {
        $col = new EvidenceCollection();
        $col->add($this->make(EvidenceType::TRUSTED_DEVICE, 'a'));
        $col->add($this->make(EvidenceType::TRUSTED_LOCATION, 'b'));
        $col->add($this->make(EvidenceType::LOGIN_FAILED, 'c'));
        $this->assertCount(2, $col->contradicting());
    }

    public function test_has_id(): void
    {
        $col = new EvidenceCollection();
        $col->add($this->make(EvidenceType::OTP_FAILED, 'xyz'));
        $this->assertTrue($col->hasId('xyz'));
        $this->assertFalse($col->hasId('nope'));
    }
}
