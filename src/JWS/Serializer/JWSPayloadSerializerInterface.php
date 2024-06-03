<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Serializer;

use rafalswierczek\JWT\JWS\Exception\InvalidJWSPayloadException;
use rafalswierczek\JWT\JWS\Model\JWSPayload;
use rafalswierczek\JWT\Shared\Exception\InvalidBase64InputException;

interface JWSPayloadSerializerInterface
{
    public function base64Encode(JWSPayload $payload): string;

    /**
     * @throws InvalidBase64InputException
     * @throws InvalidJWSPayloadException
     */
    public function base64Decode(string $base64UrlPayload): JWSPayload;

    public function jsonSerialize(JWSPayload $payload): string;

    /**
     * @throws InvalidJWSPayloadException
     */
    public function jsonDeserialize(string $jsonPayload): JWSPayload;
}
