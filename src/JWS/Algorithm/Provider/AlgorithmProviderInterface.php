<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Algorithm\Provider;

use rafalswierczek\JWT\JWS\Algorithm\AlgorithmInterface;
use rafalswierczek\JWT\JWS\Enum\Header\AlgorithmType;

interface AlgorithmProviderInterface
{
    public function getAlgorithm(AlgorithmType $algorithmType): AlgorithmInterface;
}
