<?php
declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Unit\Epistemic;

use Mixudev\SecurityDefense\Epistemic\Contracts\DecisionResponseAdapterInterface;
use Mixudev\SecurityDefense\Epistemic\Policy\DecisionAction;
use Mixudev\SecurityDefense\Epistemic\Policy\ThreatDecision;
use Mixudev\SecurityDefense\Epistemic\Response\NoopResponseAdapter;
use Mixudev\SecurityDefense\Epistemic\Response\ResponseResult;
use PHPUnit\Framework\TestCase;

final class DecisionResponseBoundaryTest extends TestCase
{
    public function test_policy_can_produce_block_without_noop_side_effect(): void
    {
        $decision = new ThreatDecision(DecisionAction::BLOCK, 'risk', ['risk' => 0.9]);
        $result = (new NoopResponseAdapter())->respond($decision);

        self::assertSame(false, $result->handled);
        self::assertSame($decision->id(), hash('sha256', $decision->action->value . ':' . $decision->reason . ':' . serialize($decision->context)));
    }

    public function test_adapter_contract_receives_same_decision_idempotently(): void
    {
        $calls = 0;
        $adapter = new class($calls) implements DecisionResponseAdapterInterface {
            public function __construct(private int &$calls) {}
            public function respond(ThreatDecision $decision): ResponseResult
            {
                $this->calls++;
                return new ResponseResult(true, $decision->id());
            }
        };
        $decision = new ThreatDecision(DecisionAction::BLOCK, 'risk');
        $first = $adapter->respond($decision);
        $second = $adapter->respond($decision);

        self::assertSame(2, $calls);
        self::assertSame($first->decisionId, $second->decisionId);
    }

    public function test_adapter_failure_can_be_returned_as_fail_safe_result(): void
    {
        try {
            throw new \RuntimeException('adapter failed');
        } catch (\Throwable $e) {
            $result = new ResponseResult(false, 'decision-id', $e->getMessage());
        }

        self::assertFalse($result->handled);
        self::assertSame('adapter failed', $result->error);
    }
}
