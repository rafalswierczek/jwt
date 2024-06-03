<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\Test;

use PHPUnit\Framework\TestCase;
use rafalswierczek\JWT\JWS\Enum\Header\AlgorithmType;

class AlgorithmTypeTest extends TestCase
{
    public function testTryFromNameValue(): void
    {
        /** @var AlgorithmType $algorithmType */
        $algorithmType = AlgorithmType::tryFromName('hS256');

        $this->assertSame($algorithmType, AlgorithmType::HS256);
    }

    public function testTryFromNameNull(): void
    {
        $algorithmType = AlgorithmType::tryFromName('unknown');

        $this->assertNull($algorithmType);
    }
}
