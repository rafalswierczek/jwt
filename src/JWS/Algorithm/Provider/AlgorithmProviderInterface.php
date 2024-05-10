<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Algorithm\Provider;

use rafalswierczek\JWT\JWS\Algorithm\AlgorithmInterface;
use rafalswierczek\JWT\JWS\Enum\Header\AlgorithmType;
use rafalswierczek\JWT\JWS\Exception\MissingAlgorithmImplementationException;

interface AlgorithmProviderInterface
{
    /**
     * @throws MissingAlgorithmImplementationException
     */
    public function getAlgorithm(AlgorithmType $algorithmType): AlgorithmInterface;
}
