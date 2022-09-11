<?php

declare(strict_types=1);

namespace rafalswierczek\jwt\tests;

require dirname(__DIR__).'/vendor/autoload.php';

use rafalswierczek\jwt\Algorithm\AlgorithmFQCN;
use rafalswierczek\jwt\{JWTValidator, JWTIssuer};

class JWTIssuerTest
{
    public function testGetJWT(): self
    {
        $jwtSecret = '123';
        $algorithm = AlgorithmFQCN::HS256;
        $jwtUser = (new JWTUser())
            ->setId('a-b-3')
        ;

        $jwtIssuer = new JWTIssuer($jwtSecret, $jwtUser, $algorithm);

        $jwtToken = $jwtIssuer->getJWT();
        
        $jwtValidator = new JWTValidator();
        $isValid = $jwtValidator->isValid($jwtToken, $jwtSecret, $algorithm);

        print_r(__FUNCTION__ . ((true === $isValid) ? "| OK\n" : "| ERROR $isValid\n"));

        return $this;
    }

    public function testAddJsonToPayload(): self
    {
        $jwtSecret = '123';
        $algorithm = AlgorithmFQCN::HS256;
        $jwtUser = (new JWTUser())
            ->setId('a-b-3')
        ;
        $issuedAt = time();

        $jsonPayload = sprintf('{"email": "test@test.test", "iat": %d}', $issuedAt);
        $expectedJson = sprintf('{"email":"test@test.test","iat":%d,"sub":"%s"}', $issuedAt, $jwtUser->getId());

        $jwtIssuer = new JWTIssuer($jwtSecret, $jwtUser, $algorithm);
        $jwtIssuer->addJsonToPayload($jsonPayload);
        $json = $jwtIssuer->getPayload();

        print_r(__FUNCTION__ . (($expectedJson === $json) ? "| OK\n" : "| ERROR $json\n"));

        return $this;
    }
}

(new JWTIssuerTest())
    ->testGetJWT()
    ->testAddJsonToPayload()
;