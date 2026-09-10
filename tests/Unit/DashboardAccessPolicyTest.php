<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Unit;

use Mixudev\SecurityDefense\Services\DashboardAccessPolicy;
use PHPUnit\Framework\TestCase;

class DashboardAccessPolicyTest extends TestCase
{
    public function test_exact_ip_is_allowed(): void
    {
        $policy = new DashboardAccessPolicy(['203.0.113.10'], []);

        $this->assertTrue($policy->allows('203.0.113.10'));
        $this->assertFalse($policy->allows('203.0.113.11'));
    }

    public function test_ipv4_cidr_is_allowed(): void
    {
        $policy = new DashboardAccessPolicy([], ['203.0.113.0/24']);

        $this->assertTrue($policy->allows('203.0.113.88'));
        $this->assertFalse($policy->allows('203.0.114.1'));
    }

    public function test_ipv6_cidr_is_allowed(): void
    {
        $policy = new DashboardAccessPolicy([], ['2001:db8::/32']);

        $this->assertTrue($policy->allows('2001:db8::20'));
        $this->assertFalse($policy->allows('2001:db9::20'));
    }

    public function test_invalid_ip_or_cidr_denies_without_throwing(): void
    {
        $policy = new DashboardAccessPolicy(['not-an-ip'], ['bad-cidr']);

        $this->assertFalse($policy->allows('203.0.113.1'));
    }

    public function test_exact_ipv6_is_allowed(): void
    {
        $policy = new DashboardAccessPolicy(['2001:db8::10'], []);

        $this->assertTrue($policy->allows('2001:db8::10'));
        $this->assertFalse($policy->allows('2001:db8::11'));
    }

    public function test_loopback_exact_and_cidr_are_allowed(): void
    {
        $policy = new DashboardAccessPolicy(['127.0.0.1', '::1'], ['10.0.0.0/8', 'fc00::/7']);

        $this->assertTrue($policy->allows('127.0.0.1'));
        $this->assertTrue($policy->allows('::1'));
        $this->assertTrue($policy->allows('10.20.30.40'));
        $this->assertTrue($policy->allows('fc00::1'));
    }

    public function test_cidr_boundary_host_and_broadcast_are_allowed(): void
    {
        $policy = new DashboardAccessPolicy([], ['203.0.113.0/28']);

        $this->assertTrue($policy->allows('203.0.113.0'));
        $this->assertTrue($policy->allows('203.0.113.15'));
        $this->assertFalse($policy->allows('203.0.113.16'));
    }

    public function test_empty_policy_allows_nothing_passive_ip_is_allowed(): void
    {
        $policy = new DashboardAccessPolicy([], []);

        $this->assertFalse($policy->allows('203.0.113.10'));
        $this->assertFalse($policy->allows(''));
    }
}