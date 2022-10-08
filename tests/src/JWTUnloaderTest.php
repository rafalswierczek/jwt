<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\Test;

use rafalswierczek\JWT\{JWTUnloader, JWTValidator};
use rafalswierczek\JWT\Exception\InvalidJWTSyntaxException;

class JWTUnloaderTest extends JWTTest
{
    public function testInvalidJWT(): void
    {
        $this->expectException(InvalidJWTSyntaxException::class);
        
        new JWTUnloader('', new JWTValidator());
    }

    public function testGetHeader(): void
    {
        $jwtUnloader = new JWTUnloader(static::JWT, new JWTValidator());

        $header = $jwtUnloader->getHeader();

        $this->assertSame(static::HEADER, $header);
    }

    public function testGetPayload(): void
    {
        $jwtUnloader = new JWTUnloader(static::JWT, new JWTValidator());

        $payload = $jwtUnloader->getPayload();

        $this->assertSame(static::PAYLOAD, $payload);
    }

    public function testGetSignature(): void
    {
        $jwtUnloader = new JWTUnloader(static::JWT, new JWTValidator());

        $signature = $jwtUnloader->getSignature();

        $this->assertSame(static::SIGNATURE, $signature);
    }

    public function testGetUserId(): void
    {
        $jwtUnloader = new JWTUnloader(static::JWT, new JWTValidator());

        $userId = $jwtUnloader->getUserId();

        $this->assertSame(static::PAYLOAD['sub'], $userId);
    }
}
