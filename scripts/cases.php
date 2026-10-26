<?php

declare(strict_types=1);

// Values shared by the interop scripts: generate_vectors.php encrypts them with Laravel
// (Laravel -> Rust) and verify_node_vectors.php compares what Laravel decrypts from Rust
// against them (Rust -> Laravel). scripts/genvectors.js builds the same values by name,
// except those marked "Laravel only".

return [
    'null' => null,
    'true' => true,
    'false' => false,
    'int_zero' => 0,
    'int_negative' => -42,
    'int_max' => PHP_INT_MAX,
    'int_min' => PHP_INT_MIN,
    'float' => 2.5,
    'float_whole' => 2.0,
    'float_tenth' => 0.1,
    'float_large' => 1.0e25,
    'float_small' => 1.5e-7,
    'float_negative_zero' => -0.0,
    'float_pi' => M_PI,
    'float_max' => PHP_FLOAT_MAX,
    'float_min_subnormal' => 4.9E-324,
    'float_inf' => INF,
    'float_negative_inf' => -INF,
    'float_nan' => NAN,
    'string_empty' => '',
    'string_unicode' => 'Grüße 世界 🚀 café',
    'string_quotes' => 'say "hi"; s:3:"x";',
    'string_binary' => "\x00\xff\xfe\x80",
    'list' => [1, 'two', true, null, [3, 4]],
    'empty_array' => [],
    'assoc' => ['user' => 'alice', 'id' => 7, 'active' => true, 'score' => 2.5, 'tags' => ['x', 'y'], 'meta' => null],
    'mixed_keys' => [5 => 'a', 'x' => 'b', 7 => ['nested' => [1, 2]]],
    'non_sequential_list' => [1 => 'a', 0 => 'b'],
    'nested' => ['l1' => ['l2' => ['l3' => ['deep', 1.5, false]]]],
];
