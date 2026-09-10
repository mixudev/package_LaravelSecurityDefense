<?php
declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Unit\Epistemic;

use DateTimeImmutable;
use Mixudev\SecurityDefense\Epistemic\Correlation\ThreatCorrelator;
use Mixudev\SecurityDefense\Epistemic\Evidence\Evidence;
use Mixudev\SecurityDefense\Epistemic\ValueObjects\Confidence;
use Mixudev\SecurityDefense\Epistemic\ValueObjects\EvidenceType;
use PHPUnit\Framework\TestCase;

class ThreatCorrelatorTest extends TestCase
{
    private function make(EvidenceType $type): Evidence { return new Evidence($type, 'test', new DateTimeImmutable(), Confidence::from(0.8)); }
    public function test_account_compromise_hypothesis(): void { $b = (new ThreatCorrelator())->correlate([$this->make(EvidenceType::LOGIN_FAILED), $this->make(EvidenceType::LOGIN_FAILED), $this->make(EvidenceType::LOGIN_FAILED), $this->make(EvidenceType::LOGIN_FAILED), $this->make(EvidenceType::LOGIN_FAILED), $this->make(EvidenceType::NEW_DEVICE), $this->make(EvidenceType::OTP_FAILED)], 900); $this->assertContains('account_compromise', array_map(fn($x) => $x->hypothesis->value, $b)); }
    public function test_single_login_failed_no_hypothesis(): void { $b = (new ThreatCorrelator())->correlate([$this->make(EvidenceType::LOGIN_FAILED)], 900); $this->assertNotContains('account_compromise', array_map(fn($x) => $x->hypothesis->value, $b)); }
    public function test_payload_injection_alone_triggers_payload_attack(): void { $b = (new ThreatCorrelator())->correlate([$this->make(EvidenceType::PAYLOAD_INJECTION)], 900); $this->assertContains('payload_attack', array_map(fn($x) => $x->hypothesis->value, $b)); }
    public function test_events_outside_window_not_counted(): void { $old = new Evidence(EvidenceType::LOGIN_FAILED, 'test', new DateTimeImmutable('-7200 seconds'), Confidence::from(0.8)); $ev = array_fill(0, 5, $old); $ev[] = new Evidence(EvidenceType::NEW_DEVICE, 'test', new DateTimeImmutable('-7200 seconds'), Confidence::from(0.8)); $this->assertEmpty((new ThreatCorrelator())->correlate($ev, 900)); }
    public function test_contradicting_evidence_included_in_belief(): void { $beliefs = (new ThreatCorrelator())->correlate([$this->make(EvidenceType::LOGIN_FAILED), $this->make(EvidenceType::NEW_DEVICE), $this->make(EvidenceType::TRUSTED_DEVICE)], 900); $ac = null; foreach ($beliefs as $b) { if ($b->hypothesis->value === 'account_compromise') { $ac = $b; break; } } $this->assertNotNull($ac); $this->assertGreaterThan(0, count($ac->contradictingEvidence)); }
}
