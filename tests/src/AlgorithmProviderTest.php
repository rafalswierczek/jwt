<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\Test;

use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use rafalswierczek\JWT\JWS\Algorithm\HS256;
use rafalswierczek\JWT\JWS\Algorithm\Provider\AlgorithmProvider;
use rafalswierczek\JWT\JWS\Algorithm\Provider\AlgorithmProviderInterface;
use rafalswierczek\JWT\JWS\Enum\Header\AlgorithmType;
use rafalswierczek\JWT\JWS\Exception\MissingAlgorithmImplementationException;
use rafalswierczek\JWT\JWS\Serializer\JWSHeaderSerializer;
use rafalswierczek\JWT\JWS\Serializer\JWSPayloadSerializer;

class AlgorithmProviderTest extends TestCase
{
    private AlgorithmProviderInterface $algorithmProvider;

    protected function setUp(): void
    {
        $this->algorithmProvider = new AlgorithmProvider(new JWSHeaderSerializer(), new JWSPayloadSerializer());
    }

    public function testGetJsonJWSUsingHS256(): void
    {
        $algorithmInstance = $this->algorithmProvider->getAlgorithm(AlgorithmType::HS256);

        $this->assertInstanceOf(HS256::class, $algorithmInstance);
    }

    #[DataProvider('unimplementedAlgorithmTypes')]
    public function testMissingAlgorithmImplementation(AlgorithmType $unimplementedAlgorithmType): void
    {
        $this->expectException(MissingAlgorithmImplementationException::class);
        $this->expectExceptionMessage('Missing algorithm implementation: ' . $unimplementedAlgorithmType->value);

        $this->algorithmProvider->getAlgorithm($unimplementedAlgorithmType);
    }

    /**
     * @return array<array<AlgorithmType>>
     */
    public static function unimplementedAlgorithmTypes(): array
    {
        return [
            // [AlgorithmType::HS256],
            [AlgorithmType::HS384],
            [AlgorithmType::HS512],
            [AlgorithmType::RS256],
            [AlgorithmType::RS384],
            [AlgorithmType::RS512],
            [AlgorithmType::ES256],
            [AlgorithmType::ES384],
            [AlgorithmType::ES512],
            [AlgorithmType::PS256],
            [AlgorithmType::PS384],
            [AlgorithmType::PS512],
        ];
    }
}
