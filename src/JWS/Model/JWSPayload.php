<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWS\Model;

use rafalswierczek\JWT\JWS\Exception\InvalidJWSPayloadException;

class JWSPayload
{
    /**
     * @param array<int, string>|null $audience
     * @param array<string, mixed>|null $data
     */
    public function __construct(
        private string $id,
        private string $issuer,
        private string $subject,
        private \DateTimeImmutable $issuedAt,
        private \DateTimeImmutable $expirationTime,
        private ?\DateTimeImmutable $notBefore = null,
        private ?array $audience = null,
        private ?array $data = null,
    ) {
        if ($this->expirationTime <= $this->issuedAt) {
            throw new InvalidJWSPayloadException(sprintf('Expiration Time must be after Issued At'));
        }

        if (null !== $this->notBefore && ($this->expirationTime <= $this->notBefore)) {
            throw new InvalidJWSPayloadException(sprintf('Expiration Time must be after Not Before'));
        }
    }

    public function getId(): string
    {
        return $this->id;
    }

    public function getIssuer(): string
    {
        return $this->issuer;
    }

    public function getSubject(): string
    {
        return $this->subject;
    }

    public function getIssuedAt(): \DateTimeImmutable
    {
        return $this->issuedAt;
    }

    public function getExpirationTime(): \DateTimeImmutable
    {
        return $this->expirationTime;
    }

    public function getNotBefore(): ?\DateTimeImmutable
    {
        return $this->notBefore;
    }

    /**
     * @return array<int, string>|null
     */
    public function getAudience(): ?array
    {
        return $this->audience;
    }

    /**
     * @return array<string, mixed>|null
     */
    public function getData(): ?array
    {
        return $this->data;
    }
}
