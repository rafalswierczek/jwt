<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Algorithm;

use rafalswierczek\JWT\JWS\Serializer\JWSSerializerInterface;
use rafalswierczek\JWT\JWS\Model\JWSHeader;
use rafalswierczek\JWT\JWS\Model\JWSPayload;

abstract class AbstractAlgorithm implements AlgorithmInterface
{
    public function __construct(private JWSSerializerInterface $serializer)
    {
    }

    protected function getHeaderAndPayloadCombined(JWSHeader $header, JWSPayload $payload): string
    {
        $base64UrlHeader = $this->serializer->base64EncodeHeader($header);
        $base64UrlPayload = $this->serializer->base64EncodePayload($payload);

        return sprintf('%s.%s', $base64UrlHeader, $base64UrlPayload);
    }
}
