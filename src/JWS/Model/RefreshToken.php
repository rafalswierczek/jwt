<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Model;

use rafalswierczek\JWT\JWS\Enum\Header\AlgorithmType;

final readonly class RefreshToken
{
    public function __construct(
        public AlgorithmType $algorithmType,
        public \DateTimeImmutable $expiredAt,
        public string $randomBinary,
        public string $signature
    ) {
    }
}
