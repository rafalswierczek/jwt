<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Algorithm\Provider;

use rafalswierczek\JWT\JWS\Algorithm\AlgorithmInterface;
use rafalswierczek\JWT\JWS\Algorithm\HS256;
use rafalswierczek\JWT\JWS\Enum\Header\AlgorithmType;
use rafalswierczek\JWT\JWS\Exception\MissingAlgorithmImplementationException;
use rafalswierczek\JWT\JWS\Serializer\JWSSerializerInterface;

final class AlgorithmProvider implements AlgorithmProviderInterface
{
    private const IMPLEMENTATION_MAP = [
        HS256::class => AlgorithmType::HS256,
    ];

    public function __construct(private JWSSerializerInterface $serializer)
    {
    }

    /**
     * @throws MissingAlgorithmImplementationException
     */
    public function getAlgorithm(AlgorithmType $algorithmType): AlgorithmInterface
    {
        foreach (self::IMPLEMENTATION_MAP as $fqcn => $definedAlgorithm) {
            if ($algorithmType === $definedAlgorithm) {
                return new $fqcn($this->serializer);
            }
        }

        throw new MissingAlgorithmImplementationException('Missing algorithm implementation: ' . $algorithmType->value);
    }
}
