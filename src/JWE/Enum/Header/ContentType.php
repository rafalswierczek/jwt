<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWE\Enum\Header;

enum ContentType: string
{
    case MESSAGE = 'MSG';
    case JWS = 'JWS';
}
