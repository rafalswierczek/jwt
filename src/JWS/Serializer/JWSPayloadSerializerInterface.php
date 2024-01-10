<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Serializer;

use rafalswierczek\JWT\JWS\Exception\InvalidJWSPayloadException;
use rafalswierczek\JWT\JWS\Model\JWSPayload;

interface JWSPayloadSerializerInterface
{
    /**
     * @throws InvalidJWSPayloadException
     */
    public function jsonSerialize(JWSPayload $payload): string;

    /**
     * @throws InvalidJWSPayloadException
     */
    public function jsonDeserialize(string $payload): JWSPayload;
}
