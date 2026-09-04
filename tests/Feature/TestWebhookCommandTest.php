<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature;

use Mixudev\SecurityDefense\Tests\TestCase;

class TestWebhookCommandTest extends TestCase
{
    public function test_artisan_command_tests_all_channels(): void
    {
        $this->artisan('security:test-webhook', ['--all' => true])
            ->expectsOutputToContain('Laravel Security Defense: Channel Connectivity Diagnostic')
            ->expectsOutputToContain('Testing all alert channels')
            ->assertSuccessful();
    }

    public function test_artisan_command_tests_specific_channel(): void
    {
        $this->artisan('security:test-webhook', ['channel' => 'database'])
            ->expectsOutputToContain('Testing single channel: database')
            ->expectsOutputToContain('DATABASE')
            ->assertSuccessful();
    }

    public function test_artisan_command_fails_on_invalid_channel(): void
    {
        $this->artisan('security:test-webhook', ['channel' => 'unknown_hack'])
            ->expectsOutputToContain('Error executing channel test')
            ->assertFailed();
    }
}
