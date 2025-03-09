<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Exception;

use rafalswierczek\JWT\JWS\Enum\Header\AlgorithmType;

final class InvalidKeySizeException extends JWSValidationException
{
    public function __construct(AlgorithmType $algorithmType, int $expectedSize, int $actualSize)
    {
        parent::__construct("{$algorithmType->name} algorithm requires {$expectedSize} bytes of key size. {$actualSize} bytes given.");
    }
}
