<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\Exception;

class InvalidJWTSyntaxException extends \Exception
{
    public function __construct(string $jwt)
    {
        parent::__construct(sprintf('This JWT has invalid syntax: %s', $jwt));
    }
}
