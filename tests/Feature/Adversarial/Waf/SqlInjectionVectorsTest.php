<?php

declare(strict_types=1);

namespace Mixudev\SecurityDefense\Tests\Feature\Adversarial\Waf;

use PHPUnit\Framework\Attributes\DataProvider;
use Mixudev\SecurityDefense\Tests\Feature\Adversarial\Concerns\RegistersWafProbeRoute;
use Mixudev\SecurityDefense\Tests\TestCase;

/**
 * SQL injection corpus through the REAL middleware.
 *
 * Attacker POV: every classic and modern SQLi shape, delivered three ways
 * (query string, form body, JSON body) because each exercises a different
 * scanner path (parsed query vs parsed body vs raw content).
 */
class SqlInjectionVectorsTest extends TestCase
{
    use RegistersWafProbeRoute;

    protected function setUp(): void
    {
        parent::setUp();
        $this->registerWafProbeRoutes();
        $this->withoutAutoJail();
    }

    #[DataProvider('classicPayloadProvider')]
    public function test_query_string_sqli_is_blocked(string $payload): void
    {
        $result = $this->probeGet($payload, '198.18.1.1');

        $this->assertSame(403, $result['status'], "Query SQLi not blocked: {$payload}");
    }

    #[DataProvider('classicPayloadProvider')]
    public function test_form_body_sqli_is_blocked(string $payload): void
    {
        $result = $this->probeForm('comment', $payload, '198.18.1.2');

        $this->assertSame(403, $result['status'], "Form SQLi not blocked: {$payload}");
    }

    #[DataProvider('classicPayloadProvider')]
    public function test_json_body_sqli_is_blocked(string $payload): void
    {
        $result = $this->probeJson('comment', $payload, '198.18.1.3');

        $this->assertSame(403, $result['status'], "JSON SQLi not blocked: {$payload}");
    }

    /**
     * @return array<string, array{0: string}>
     */
    public static function classicPayloadProvider(): array
    {
        return [
            'tautology quote' => ["' OR 1=1--"],
            'tautology double quote' => ['" OR 1=1--'],
            'and tautology' => ["' AND 1=1--"],
            'numeric tautology' => ['1 OR 1=1'],
            'numeric tautology and' => ['1 AND 1=1'],
            'union select' => ['1 UNION SELECT username FROM users'],
            'union all select' => ['1 UNION ALL SELECT password FROM admins'],
            'union select columns' => ['1 UNION SELECT 1,2,3'],
            'select from' => ['SELECT email FROM users WHERE id=1'],
            'insert into' => ['INSERT INTO users (role) VALUES (1)'],
            'update set' => ['UPDATE users SET is_admin=1'],
            'delete from' => ['DELETE FROM sessions WHERE 1=1'],
            'drop table' => ['DROP TABLE users'],
            'drop database' => ['DROP DATABASE production'],
            'truncate table' => ['TRUNCATE TABLE logs'],
            'stacked query' => ['1; DELETE FROM users'],
            'stacked insert' => ['1; INSERT INTO audit VALUES (1)'],
            'comment terminator' => ["'--"],
            'hash comment' => ["' #"],
            'waitfor delay' => ["'; WAITFOR DELAY '0:0:5'--"],
            'sleep' => ["1 AND SLEEP(5)"],
            'benchmark' => ["1 AND BENCHMARK(1000000,MD5(1))"],
            'subquery' => ["' AND (SELECT COUNT(*) FROM users)>0--"],
            'boolean blind' => ["' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64--"],
            'order by' => ["1 ORDER BY 100"],
            'information_schema' => ["' UNION SELECT table_name FROM information_schema.tables--"],
            'case when' => ["1 AND CASE WHEN (1=1) THEN 1 ELSE 0 END"],
            'concat' => ["' UNION SELECT CONCAT(username,0x3a,password) FROM users--"],
            'backtick table' => ["' UNION SELECT * FROM `users`--"],
            'mysql comment inline' => ["1/**/UNION/**/SELECT/**/1"],
            'newline union' => ["1'\nUNION SELECT 1"],
            'tab union' => ["1'\tUNION SELECT 1"],
            'mixed case union' => ["1' UnIoN SeLeCt 1"],
            'parenthesised' => ["') OR ('1'='1"],
            'nested select' => ["' OR (SELECT 1 FROM (SELECT SLEEP(1))a)--"],
            'time based sleep decimal' => ["1;SELECT SLEEP(2.5)"],
            'outfile' => ["' UNION SELECT 1 INTO OUTFILE '/tmp/x'--"],
            'load file' => ["' UNION SELECT LOAD_FILE('/etc/passwd')--"],
            'hex literal concatenated' => ["' UNION SELECT 0x274f5220313d31--"],
            'char obfuscation' => ["CHAR(39) OR 1=1"],
            'xor bypass' => ['1 XOR 1=1'],
            'not between' => ["' AND 1 NOT BETWEEN 0 AND 2--"],
            'like bypass' => ["' OR username LIKE '%admin%"],
        ];
    }

    public function test_benign_prose_with_sql_words_is_not_blocked(): void
    {
        foreach (['select items from a shop', 'drop by my house later', 'update my profile please'] as $text) {
            $result = $this->probeGet($text, '198.18.1.4');
            $this->assertSame(
                200,
                $result['status'],
                "False positive on benign prose: {$text}"
            );
        }
    }

    public function test_benign_numeric_expressions_are_not_blocked(): void
    {
        foreach (['1=1', '5 > 3', 'age<30 and age>18', 'price = 49.99'] as $text) {
            $result = $this->probeGet($text, '198.18.1.5');
            $this->assertSame(
                200,
                $result['status'],
                "False positive on benign expression: {$text}"
            );
        }
    }

    public function test_benign_email_and_search_queries_are_not_blocked(): void
    {
        foreach (['user@example.com', 'hello world', 'iphone 15 pro max'] as $text) {
            $result = $this->probeForm('q', $text, '198.18.1.6');
            $this->assertSame(200, $result['status'], "False positive: {$text}");
        }
    }
}
