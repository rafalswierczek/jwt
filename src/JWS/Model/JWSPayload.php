<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Model;

use rafalswierczek\JWT\JWS\Exception\InvalidJWSPayloadException;

final readonly class JWSPayload
{
    /**
     * @param array<string>|null $audience
     * @param array<mixed>|null $data
     *
     * @throws InvalidJWSPayloadException
     */
    public function __construct(
        public string $id,
        public string $issuer,
        public string $subject,
        public \DateTimeImmutable $issuedAt,
        public \DateTimeImmutable $expirationTime,
        public ?\DateTimeImmutable $notBefore = null,
        public ?array $audience = null,
        public ?array $data = null,
    ) {
        if ($this->expirationTime <= $this->issuedAt) {
            throw new InvalidJWSPayloadException(sprintf('Expiration Time must be after Issued At'));
        }

        if (null !== $this->notBefore && ($this->expirationTime <= $this->notBefore)) {
            throw new InvalidJWSPayloadException(sprintf('Expiration Time must be after Not Before'));
        }
    }
}
