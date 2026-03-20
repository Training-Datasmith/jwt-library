<?php

declare(strict_types=1);

/**
 * Example: sign a JWS (JSON Web Signature) token and verify it using the jwt-library (web-token).
 *
 * Run from the jwt-library project root:
 *   php examples/sign_and_verify.php
 */

require __DIR__ . '/../vendor/autoload.php';

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;

// --- Build a symmetric JWK (HMAC-SHA256) ---
$jwk = new JWK([
    'kty' => 'oct',
    'k'   => base64_encode(random_bytes(32)),
]);

$algorithmManager = new AlgorithmManager([new HS256()]);

// --- Sign a payload ---
$builder    = new JWSBuilder($algorithmManager);
$serializer = new CompactSerializer();

$jws = $builder
    ->create()
    ->withPayload(json_encode([
        'iss' => 'https://example.com',
        'sub' => 'user-42',
        'iat' => time(),
        'exp' => time() + 3600,
    ]))
    ->addSignature($jwk, ['alg' => 'HS256'])
    ->build();

$token = $serializer->serialize($jws, 0);

echo "Token (first 60 chars): " . substr($token, 0, 60) . "...\n";

// --- Verify the token ---
$serializerManager = new JWSSerializerManager([$serializer]);
$verifier          = new JWSVerifier($algorithmManager);

$loadedJws = $serializerManager->unserialize($token);
$isValid   = $verifier->verifyWithKey($loadedJws, $jwk, 0);

echo "Signature valid: " . ($isValid ? 'yes' : 'no') . "\n";

// --- Inspect payload ---
$payload = json_decode($loadedJws->getPayload(), true);
echo "Subject: " . $payload['sub'] . "\n";
echo "Issuer:  " . $payload['iss'] . "\n";
