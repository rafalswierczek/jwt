<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\Test;

use rafalswierczek\JWT\Algorithm\AlgorithmFQCN;
use rafalswierczek\JWT\{JWTValidator, JWTIssuer};
use rafalswierczek\JWT\Test\JWTUser;

class JWTIssuerTest extends JWTTest
{
    public function testGetJWT(): void
    {
        $jwtUser = (new JWTUser())
            ->setId(static::PAYLOAD['sub'])
        ;

        $jwtIssuer = new JWTIssuer(static::JWT_SECRET, $jwtUser, static::JWT_ALGORITHM);

        $jwtToken = $jwtIssuer->getJWT();
        
        $this->assertNull((new JWTValidator())->validate($jwtToken, static::JWT_SECRET, static::JWT_ALGORITHM));
    }

    public function testAddJsonToPayload(): void
    {
        $jwtUser = (new JWTUser())
            ->setId(static::PAYLOAD['sub'])
        ;

        $issuedAt = time();

        $jsonPayload = sprintf('{"email": "test@test.test", "iat": %d}', $issuedAt);
        $expectedJson = sprintf('{"email":"test@test.test","iat":%d,"sub":"%s"}', $issuedAt, $jwtUser->getId());

        $jwtIssuer = new JWTIssuer(static::JWT_SECRET, $jwtUser, static::JWT_ALGORITHM);
        $jwtIssuer->addJsonToPayload($jsonPayload);
        $json = $jwtIssuer->getPayload();

        $this->assertSame($expectedJson, $json);
    }
}
