<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Serializer;

use rafalswierczek\JWT\JWS\Exception\InvalidJWSHeaderException;
use rafalswierczek\JWT\JWS\Model\JWSHeader;
use rafalswierczek\JWT\Shared\Exception\InvalidBase64InputException;

interface JWSHeaderSerializerInterface
{
    public function base64Encode(JWSHeader $header): string;

    /**
     * @throws InvalidBase64InputException
     * @throws InvalidJWSHeaderException
     */
    public function base64Decode(string $base64UrlHeader): JWSHeader;

    public function jsonSerialize(JWSHeader $header): string;

    /**
     * @throws InvalidJWSHeaderException
     */
    public function jsonDeserialize(string $jsonHeader): JWSHeader;
}
