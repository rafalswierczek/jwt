<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\Test;

use rafalswierczek\JWT\JWTValidator;
use rafalswierczek\JWT\Exception\{InvalidJWTSyntaxException, InvalidJWTException};

class JWTValidatorTest extends JWTTest
{
    public function invalidJWTList(): array
    {
       return [
           [''], ['a.b.c'], ['...'], ['aa.bb.c'], ['aa.bb.cc.']
       ];
    }

    public function testIsValid(): void
    {
        $jwtValidator = new JWTValidator();

        $this->assertNull($jwtValidator->validate(static::JWT, static::JWT_SECRET, static::JWT_ALGORITHM));

        $this->expectException(InvalidJWTException::class);

        $jwtValidator->validate(static::JWT, '1234', static::JWT_ALGORITHM);
    }

    public function testHasValidSyntax(): void
    {
        $jwtValidator = new JWTValidator();

        $this->assertNull($jwtValidator->validateSyntax(static::JWT));

        $this->assertNull($jwtValidator->validateSyntax('aa.bb.cc'));
    }

    /**
     * @dataProvider invalidJWTList
     */
    public function testHasInvalidSyntax(string $invalidJWT): void
    {
        $jwtValidator = new JWTValidator();

        $this->expectException(InvalidJWTSyntaxException::class);

        $jwtValidator->validateSyntax($invalidJWT);
    }
}
