<?php

$finder = (new PhpCsFixer\Finder())
    ->in(__DIR__)
;

return (new PhpCsFixer\Config())
    ->setRules([
        '@Symfony' => true,
        '@PSR2' => true,
        '@PSR12' => true,
        '@PER-CS' => true,
        '@PHP82Migration' => true,
        'line_ending' => false,
        'yoda_style' => true,
        'single_line_empty_body' => false,
        'phpdoc_align' => ['align' => 'left'],
    ])
    ->setFinder($finder)
;
