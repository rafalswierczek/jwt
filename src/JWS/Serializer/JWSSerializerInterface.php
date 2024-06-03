<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Serializer;

use rafalswierczek\JWT\JWS\Exception\InvalidJWSCompactException;
use rafalswierczek\JWT\JWS\Exception\InvalidJWSHeaderException;
use rafalswierczek\JWT\JWS\Exception\InvalidJWSJsonException;
use rafalswierczek\JWT\JWS\Exception\InvalidJWSPayloadException;
use rafalswierczek\JWT\JWS\Model\JWS;
use rafalswierczek\JWT\Shared\Exception\InvalidBase64InputException;

interface JWSSerializerInterface
{
    public function compactSerializeJWS(JWS $jws): string;

    /**
     * @throws InvalidJWSCompactException
     * @throws InvalidBase64InputException
     * @throws InvalidJWSHeaderException
     * @throws InvalidJWSPayloadException
     */
    public function compactDeserializeJWS(string $compactJWS): JWS;

    public function jsonSerializeJWS(JWS $jws): string;

    /**
     * @throws InvalidJWSJsonException
     * @throws InvalidBase64InputException
     * @throws InvalidJWSHeaderException
     * @throws InvalidJWSPayloadException
     */
    public function jsonDeserializeJWS(string $jsonJWS): JWS;
}
