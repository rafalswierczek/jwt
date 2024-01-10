<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Serializer;

use rafalswierczek\JWT\JWS\Exception\InvalidJWSHeaderException;
use rafalswierczek\JWT\JWS\Model\JWSHeader;

interface JWSHeaderSerializerInterface
{
    /**
     * @throws InvalidJWSHeaderException
     */
    public function jsonSerialize(JWSHeader $header): string;

    /**
     * @throws InvalidJWSHeaderException
     */
    public function jsonDeserialize(string $header): JWSHeader;
}
