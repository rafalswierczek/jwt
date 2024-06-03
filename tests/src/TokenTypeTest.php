<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\Test;

use PHPUnit\Framework\TestCase;
use rafalswierczek\JWT\JWS\Enum\Header\TokenType;

class TokenTypeTest extends TestCase
{
    public function testTryFromNameValue(): void
    {
        /** @var TokenType $tokenType */
        $tokenType = TokenType::tryFromName('jWs');

        $this->assertSame($tokenType, TokenType::JWS);
    }

    public function testTryFromNameNull(): void
    {
        $tokenType = TokenType::tryFromName('unknown');

        $this->assertNull($tokenType);
    }
}
