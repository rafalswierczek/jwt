<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\Test;

use PHPUnit\Framework\TestCase;
use rafalswierczek\JWT\JWS\Algorithm\Provider\AlgorithmProvider;
use rafalswierczek\JWT\JWS\Algorithm\Provider\AlgorithmProviderInterface;
use rafalswierczek\JWT\JWS\Enum\Header\AlgorithmType;
use rafalswierczek\JWT\JWS\Serializer\JWSHeaderSerializer;
use rafalswierczek\JWT\JWS\Serializer\JWSPayloadSerializer;

class AlgorithmProviderTest extends TestCase
{
    private AlgorithmProviderInterface $algorithmProvider;

    protected function setUp(): void
    {
        $this->algorithmProvider = new AlgorithmProvider(new JWSHeaderSerializer(), new JWSPayloadSerializer());
    }

    public function testGetAlgorithm(): void
    {
        foreach (AlgorithmType::cases() as $algorithmType) {
            $algorithm = $this->algorithmProvider->getAlgorithm($algorithmType);

            $this->assertInstanceOf($algorithmType->value, $algorithm);
        }
    }
}
