<?php
declare(strict_types=1);

namespace Mixudev\SecurityDefense\Epistemic\Response;

final class ResponseResult
{
    public function __construct(
        public readonly bool $handled = false,
        public readonly ?string $decisionId = null,
        public readonly ?string $error = null,
    ) {}

    public static function ignored(?string $decisionId = null): self
    {
        return new self(false, $decisionId);
    }
}
