<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Algorithm\Provider;

use rafalswierczek\JWT\JWS\Algorithm\AlgorithmInterface;
use rafalswierczek\JWT\JWS\Enum\Header\Algorithm;
use rafalswierczek\JWT\JWS\Exception\MissingAlgorithmImplementationException;

interface AlgorithmProviderInterface
{
    /**
     * @throws MissingAlgorithmImplementationException 
     */
    public function getAlgorithmInstance(Algorithm $algorithm): AlgorithmInterface;
}
