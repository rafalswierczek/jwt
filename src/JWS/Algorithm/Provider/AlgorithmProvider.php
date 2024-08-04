<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Algorithm\Provider;

use rafalswierczek\JWT\JWS\Algorithm\AbstractAlgorithm;
use rafalswierczek\JWT\JWS\Enum\Header\AlgorithmType;
use rafalswierczek\JWT\JWS\Serializer\JWSHeaderSerializerInterface;
use rafalswierczek\JWT\JWS\Serializer\JWSPayloadSerializerInterface;

final class AlgorithmProvider implements AlgorithmProviderInterface
{
    public function __construct(
        private JWSHeaderSerializerInterface $headerSerializer,
        private JWSPayloadSerializerInterface $payloadSerializer,
    ) {
    }

    public function getAlgorithm(AlgorithmType $algorithmType): AbstractAlgorithm
    {
        return new ($algorithmType->value)($this->headerSerializer, $this->payloadSerializer);
    }
}
