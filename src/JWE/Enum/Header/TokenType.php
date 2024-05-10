<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWE\Enum\Header;

enum TokenType: string
{
    case JWE_SODIUM = 'JWE-SODIUM';
}
