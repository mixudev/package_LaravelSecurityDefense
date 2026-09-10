<?php
declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Unit\Epistemic;

use DateTimeImmutable;
use Mixudev\SecurityDefense\Epistemic\Correlation\TemporalWindow;
use Mixudev\SecurityDefense\Epistemic\Evidence\Evidence;
use Mixudev\SecurityDefense\Epistemic\ValueObjects\Confidence;
use Mixudev\SecurityDefense\Epistemic\ValueObjects\EvidenceType;
use PHPUnit\Framework\TestCase;

class TemporalWindowTest extends TestCase
{
    private function make(EvidenceType $type, string $timeOffset = 'now'): Evidence { return new Evidence($type, 'test', new DateTimeImmutable($timeOffset), Confidence::from(0.8)); }
    public function test_filter_removes_old_evidence(): void { $r = TemporalWindow::filter([$this->make(EvidenceType::LOGIN_FAILED, 'now'), $this->make(EvidenceType::NEW_DEVICE, '-2000 seconds')], 900); $this->assertCount(1, $r); $this->assertEquals('login_failed', $r[0]->type->value); }
    public function test_filter_window_zero_removes_all(): void { $this->assertCount(0, TemporalWindow::filter([$this->make(EvidenceType::LOGIN_FAILED, '-1 second')], 0)); }
    public function test_filter_excludes_future_beyond_skew(): void { $now = 1000000; $future = new Evidence(EvidenceType::LOGIN_FAILED, 'test', new DateTimeImmutable('@1000061'), Confidence::from(0.8)); $this->assertCount(0, TemporalWindow::filter([$future], 900, 60, $now)); }
    public function test_sort_chronological(): void { $sorted = TemporalWindow::sortChronological([$this->make(EvidenceType::NEW_DEVICE, '-300 seconds'), $this->make(EvidenceType::LOGIN_FAILED, '-600 seconds'), $this->make(EvidenceType::OTP_FAILED, '-100 seconds')]); $this->assertEquals('login_failed', $sorted[0]->type->value); $this->assertEquals('otp_failed', $sorted[2]->type->value); }
    public function test_contains_sequence_found(): void { $e = TemporalWindow::sortChronological([$this->make(EvidenceType::LOGIN_FAILED, '-400 seconds'), $this->make(EvidenceType::NEW_DEVICE, '-300 seconds'), $this->make(EvidenceType::OTP_FAILED, '-200 seconds'), $this->make(EvidenceType::PASSWORD_RESET, '-100 seconds')]); $this->assertTrue(TemporalWindow::containsSequence($e, [EvidenceType::LOGIN_FAILED, EvidenceType::OTP_FAILED, EvidenceType::PASSWORD_RESET])); }
    public function test_contains_sequence_not_found_wrong_order(): void { $e = TemporalWindow::sortChronological([$this->make(EvidenceType::OTP_FAILED, '-200 seconds'), $this->make(EvidenceType::LOGIN_FAILED, '-100 seconds')]); $this->assertFalse(TemporalWindow::containsSequence($e, [EvidenceType::LOGIN_FAILED, EvidenceType::OTP_FAILED])); }
}
