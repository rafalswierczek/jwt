<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Algorithm;

use rafalswierczek\JWT\JWS\Enum\Header\AlgorithmType;
use rafalswierczek\JWT\JWS\Serializer\JWSHeaderSerializerInterface;
use rafalswierczek\JWT\JWS\Model\JWSHeader;
use rafalswierczek\JWT\JWS\Model\JWSPayload;
use rafalswierczek\JWT\JWS\Serializer\JWSPayloadSerializerInterface;

abstract class AbstractAlgorithm implements AlgorithmInterface
{
    public function __construct(
        private JWSHeaderSerializerInterface $headerSerializer,
        private JWSPayloadSerializerInterface $payloadSerializer,
    ) {
    }

    protected function getJWSInput(JWSHeader $header, JWSPayload $payload): string
    {
        $base64UrlHeader = $this->headerSerializer->base64Encode($header);
        $base64UrlPayload = $this->payloadSerializer->base64Encode($payload);

        return sprintf('%s.%s', $base64UrlHeader, $base64UrlPayload);
    }

    protected function getRefreshTokenInput(\DateTimeImmutable $expiredAt): string
    {
        $algorithmType = AlgorithmType::from(static::class);

        return sprintf('%s.%d', $algorithmType->name, $expiredAt->getTimestamp());
    }
}
