<?php

declare(strict_types=1);

namespace rafalswierczek\JWT\JWE\Enum\Header;

Enum ContentType: string
{
    case MESSAGE = 'MSG';
    case JWS = 'JWS';
}
