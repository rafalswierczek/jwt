<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Algorithm;

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

    protected function getHeaderAndPayloadCombined(JWSHeader $header, JWSPayload $payload): string
    {
        $base64UrlHeader = $this->headerSerializer->base64Encode($header);
        $base64UrlPayload = $this->payloadSerializer->base64Encode($payload);

        return sprintf('%s.%s', $base64UrlHeader, $base64UrlPayload);
    }
}
