<?php

declare(strict_types=1);

namespace rafalswierczek\jwt\Algorithm;

interface AlgorithmInterface
{
    public function hash(): string;

    public static function getName(): string;
}
