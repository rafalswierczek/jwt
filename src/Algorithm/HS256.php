<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\Algorithm;

final class HS256 implements AlgorithmInterface
{
    public const NAME = 'HS256';
    
    public function __construct(
        private string $jwtSecret,
        private string $jsonHeader,
        private string $jsonPayload
    ) {}

    public function hash(): string
    {
        return hash_hmac(
            'sha256',
            base64_encode($this->jsonHeader) . '.' . base64_encode($this->jsonPayload),
            $this->jwtSecret
        );
    }

    public static function getName(): string
    {
        return self::NAME;
    }
}
