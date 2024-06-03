<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Serializer;

use rafalswierczek\JWT\JWS\Enum\Header\AlgorithmType;
use rafalswierczek\JWT\JWS\Enum\Header\TokenType;
use rafalswierczek\JWT\JWS\Exception\InvalidJWSHeaderException;
use rafalswierczek\JWT\JWS\Model\JWSHeader;
use rafalswierczek\JWT\Shared\Base64;
use rafalswierczek\JWT\Shared\Exception\InvalidBase64InputException;

final class JWSHeaderSerializer implements JWSHeaderSerializerInterface
{
    public function jsonSerialize(JWSHeader $header): string
    {
        $headerArray = [
            'typ' => $header->tokenType->name,
            'alg' => $header->algorithmType->name,
        ];

        return json_encode($headerArray) ?: throw new \ValueError('JWS header JSON serialization failed due to usage of binary data');
    }

    /**
     * @throws InvalidJWSHeaderException
     */
    public function jsonDeserialize(string $jsonHeader): JWSHeader
    {
        /** @var array<string, string> $headerArray */
        $headerArray = json_decode($jsonHeader, true) ?? throw new InvalidJWSHeaderException('Invalid header format');

        $headerType = $headerArray['typ'] ?? throw new InvalidJWSHeaderException("Cannot find 'typ' key in JSON header");
        $headerAlgorithm = $headerArray['alg'] ?? throw new InvalidJWSHeaderException("Cannot find 'alg' key in JSON header");

        $type = TokenType::tryFromName($headerType) ?? throw new InvalidJWSHeaderException("Invalid header type: $headerType");
        $algorithm = AlgorithmType::tryFromName($headerAlgorithm) ?? throw new InvalidJWSHeaderException("Invalid header algorithm: $headerAlgorithm");

        return new JWSHeader($type, $algorithm);
    }

    public function base64Encode(JWSHeader $header): string
    {
        return Base64::UrlEncode($this->jsonSerialize($header));
    }

    /**
     * @throws InvalidBase64InputException
     * @throws InvalidJWSHeaderException
     */
    public function base64Decode(string $base64UrlHeader): JWSHeader
    {
        return $this->jsonDeserialize(Base64::UrlDecode($base64UrlHeader));
    }
}
