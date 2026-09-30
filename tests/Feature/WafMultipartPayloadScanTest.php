<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature;

use Illuminate\Http\UploadedFile;
use Mixudev\SecurityDefense\Middleware\RequestThreatScanner;
use Mixudev\SecurityDefense\Tests\TestCase;

/**
 * Regression: the payload scanner gated on getContent() alone, so a
 * multipart/form-data POST — where PHP exposes an EMPTY raw stream and puts
 * every field in $_POST — skipped payload inspection entirely. Attackers
 * sending a file upload (the most common form in Laravel apps) got an
 * uninspected channel straight to the controller.
 */
class WafMultipartPayloadScanTest extends TestCase
{
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);
        $app['config']->set('app.key', 'base64:7VzK9gG2e+x8UfXoN9uC7x/2j6yD8Hw0Z1A2B3C4D5E=');
    }

    protected function defineRoutes($router): void
    {
        $router->post('/probe-target', fn () => response('OK', 200))
            ->middleware(RequestThreatScanner::class);
        $router->put('/probe-target', fn () => response('OK', 200))
            ->middleware(RequestThreatScanner::class);
        $router->patch('/probe-target', fn () => response('OK', 200))
            ->middleware(RequestThreatScanner::class);
        $router->delete('/probe-target', fn () => response('OK', 200))
            ->middleware(RequestThreatScanner::class);
    }

    public static function attackProvider(): array
    {
        return [
            'sqli union' => ["1' UNION SELECT 1,2,3--"],
            'sqli or 1=1' => ["1' OR '1'='1"],
            'xss script' => ['<script>alert(document.cookie)</script>'],
        ];
    }

    /**
     * @dataProvider attackProvider
     */
    public function test_multipart_upload_with_payload_is_blocked(string $payload): void
    {
        $response = $this->post('/probe-target', [
            'q' => $payload,
            'title' => 'annual report',
            'avatar' => UploadedFile::fake()->image('avatar.png'),
        ]);

        $this->assertSame(
            403,
            $response->getStatusCode(),
            'Multipart POST dengan payload serangan harus diblokir, bukan lolos ke controller.'
        );
    }

    /**
     * @dataProvider attackProvider
     */
    public function test_plain_form_post_with_payload_is_blocked(string $payload): void
    {
        $response = $this->post('/probe-target', ['q' => $payload]);

        $this->assertSame(
            403,
            $response->getStatusCode(),
            'Form POST biasa dengan payload serangan harus diblokir.'
        );
    }

    public function test_json_body_with_payload_is_still_blocked(): void
    {
        $response = $this->postJson('/probe-target', ['q' => "1' UNION SELECT 1,2,3--"]);

        $this->assertSame(403, $response->getStatusCode(), 'JSON body harus tetap diblokir.');
    }

    public function test_form_urlencoded_plus_separators_are_decoded_before_scan(): void
    {
        $response = $this->call(
            'POST',
            '/probe-target',
            [],
            [],
            [],
            ['CONTENT_TYPE' => 'application/x-www-form-urlencoded'],
            "'+UNION+SELECT+1,2,3--"
        );

        $this->assertSame(403, $response->getStatusCode(), 'Separator + pada form-urlencoded tidak boleh melewati WAF.');
    }

    public function test_clean_form_urlencoded_body_is_allowed(): void
    {
        $response = $this->call(
            'POST',
            '/probe-target',
            [],
            [],
            [],
            ['CONTENT_TYPE' => 'application/x-www-form-urlencoded'],
            'title=annual+report&note=reviewed+by+finance'
        );

        $this->assertSame(200, $response->getStatusCode(), 'Form-urlencoded yang sah tidak boleh diblokir.');
    }

    /**
     * Padding on either side must not hide a payload from the bounded scan.
     */
    public function test_padding_on_either_side_of_form_body_is_blocked(): void
    {
        $payload = "1' UNION SELECT 1,2,3--";
        $padding = str_repeat('A', 5000);

        foreach ([
            $padding . $payload,
            $payload . $padding,
        ] as $body) {
            $response = $this->call(
                'POST',
                '/probe-target',
                [],
                [],
                [],
                ['CONTENT_TYPE' => 'application/x-www-form-urlencoded'],
                $body
            );

            $this->assertSame(403, $response->getStatusCode());
        }
    }

    /**
     * The decoder is wired into the middleware, not merely unit-tested alone.
     */
    public function test_encoded_sqli_variants_are_blocked_end_to_end(): void
    {
        foreach ([
            '%27%20UNION%20SELECT%201,2,3--',
            '%2527%2520UNION%2520SELECT%25201,2,3--',
        ] as $payload) {
            $response = $this->call(
                'POST',
                '/probe-target',
                [],
                [],
                [],
                ['CONTENT_TYPE' => 'application/x-www-form-urlencoded'],
                'q=' . $payload
            );

            $this->assertSame(403, $response->getStatusCode());
        }
    }

    public function test_clean_multipart_upload_is_allowed(): void
    {
        // False-positive guard: legitimate uploads must not be blocked.
        $response = $this->post('/probe-target', [
            'title' => 'Quarterly report',
            'description' => 'Uploaded from the mobile app, reviewed by finance.',
            'avatar' => UploadedFile::fake()->image('avatar.png'),
        ]);

        $this->assertSame(200, $response->getStatusCode(), 'Upload sah tidak boleh diblokir.');
    }

    /**
     * Every mutating verb shares the same body-detection path, so all must block.
     */
    public function test_other_http_verbs_with_form_payload_are_blocked(): void
    {
        $payload = "1' UNION SELECT 1,2,3--";

        foreach (['PUT', 'PATCH', 'DELETE'] as $verb) {
            $response = $this->call(
                $verb,
                '/probe-target',
                ['q' => $payload],
                [],
                [],
                [],
                [],
                http_build_query(['q' => $payload], '', '&', PHP_QUERY_RFC1738)
            );

            $this->assertSame(
                403,
                $response->getStatusCode(),
                "HTTP {$verb} dengan payload SQLi harus diblokir."
            );
        }
    }
}