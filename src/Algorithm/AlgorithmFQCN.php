<?php

declare(strict_types=1);

namespace rafalswierczek\jwt\Algorithm;

enum AlgorithmFQCN: string
{
    case HS256 = HS256::class;
}
