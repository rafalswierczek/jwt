<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\Test;

use PHPUnit\Framework\TestCase;
use rafalswierczek\JWT\JWS\Algorithm\HS256;
use rafalswierczek\JWT\JWS\Algorithm\Provider\AlgorithmProvider;
use rafalswierczek\JWT\JWS\Algorithm\Provider\AlgorithmProviderInterface;
use rafalswierczek\JWT\JWS\Enum\Header\Algorithm;
use rafalswierczek\JWT\JWS\Serializer\JWSHeaderSerializer;
use rafalswierczek\JWT\JWS\Serializer\JWSPayloadSerializer;
use rafalswierczek\JWT\JWS\Serializer\JWSSerializer;

class AlgorithmProviderTest extends TestCase
{
    private AlgorithmProviderInterface $algorithmProvider;

    protected function setUp(): void
    {
        $this->algorithmProvider = new AlgorithmProvider(new JWSSerializer(new JWSHeaderSerializer(), new JWSPayloadSerializer()));
    }

    public function testGetJsonJWSUsingHS256(): void
    {
        $algorithmInstance = $this->algorithmProvider->getAlgorithm(Algorithm::HS256);

        $this->assertInstanceOf(HS256::class, $algorithmInstance);
    }
}
