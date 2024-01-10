<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Serializer;

use rafalswierczek\JWT\JWS\Enum\Header\Algorithm;
use rafalswierczek\JWT\JWS\Enum\Header\Type;
use rafalswierczek\JWT\JWS\Exception\InvalidJWSHeaderException;
use rafalswierczek\JWT\JWS\Model\JWSHeader;

final class JWSHeaderSerializer implements JWSHeaderSerializerInterface
{
    /**
     * @throws InvalidJWSHeaderException
     */
    public function jsonSerialize(JWSHeader $header): string
    {
        $headerArray = [
            'typ' => $header->getType()->name,
            'alg' => $header->getAlgorithm()->name,
        ];

        return json_encode($headerArray) ?: throw new InvalidJWSHeaderException("JWS header JSON serialization failed due to binary data");
    }

    /**
     * @throws InvalidJWSHeaderException 
     */
    public function jsonDeserialize(string $header): JWSHeader
    {
        /** @var array<string, string> $headerArray */
        $headerArray = json_decode($header, true) ?? throw new InvalidJWSHeaderException('Invalid header format');

        $headerType = $headerArray['typ'] ?? throw new InvalidJWSHeaderException("Cannot find 'typ' key in JSON header");
        $headerAlgorithm = $headerArray['alg'] ?? throw new InvalidJWSHeaderException("Cannot find 'alg' key in JSON header");

        $type = Type::tryFromName($headerType) ?? throw new InvalidJWSHeaderException("Invalid header type: $headerType");
        $algorithm = Algorithm::tryFromName($headerAlgorithm) ?? throw new InvalidJWSHeaderException("Invalid header algorithm: $headerAlgorithm");

        return new JWSHeader($type, $algorithm);
    }
}
