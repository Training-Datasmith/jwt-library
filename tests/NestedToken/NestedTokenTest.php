<?php

declare(strict_types=1);

namespace Jose\Tests\NestedToken;

use InvalidArgumentException;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128GCM;
use Jose\Component\Encryption\Algorithm\KeyEncryption\Dir;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\JWELoader;
use Jose\Component\Encryption\Serializer\CompactSerializer as JweCompact;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\NestedToken\NestedTokenBuilder;
use Jose\Component\NestedToken\NestedTokenLoader;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer as JwsCompact;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use PHPUnit\Framework\TestCase;

final class NestedTokenTest extends TestCase
{
    public function testNestedTokenBuildAndLoad(): void
    {
        $sigKey = JWKFactory::createOctKey(256, ['alg' => 'HS256', 'use' => 'sig']);
        $encKey = JWKFactory::createOctKey(128, ['alg' => 'A128GCM', 'use' => 'enc']);
        $sigMgr = new AlgorithmManager([new HS256()]);
        $encMgr = new AlgorithmManager([new Dir(), new A128GCM()]);
        $builder = new NestedTokenBuilder(
            new JWEBuilder($encMgr),
            new JWESerializerManager([new JweCompact()]),
            new JWSBuilder($sigMgr),
            new JWSSerializerManager([new JwsCompact()])
        );
        $token = $builder->create(
            'nested-payload',
            [['key' => $sigKey, 'protected_header' => ['alg' => 'HS256']]],
            JwsCompact::NAME,
            ['alg' => 'dir', 'enc' => 'A128GCM'],
            [],
            [['key' => $encKey]],
            JweCompact::NAME
        );
        $loader = new NestedTokenLoader(
            new JWELoader(new JWESerializerManager([new JweCompact()]), new JWEDecrypter($encMgr), null),
            new JWSLoader(new JWSSerializerManager([new JwsCompact()]), new JWSVerifier($sigMgr), null)
        );
        $sig = null;
        $jws = $loader->load($token, new JWKSet([$encKey]), new JWKSet([$sigKey]), $sig);
        self::assertSame('nested-payload', $jws->getPayload());
        self::assertSame(0, $sig);
    }

    public function testRejectsWrongContentType(): void
    {
        $sigKey = JWKFactory::createOctKey(256, ['alg' => 'HS256', 'use' => 'sig']);
        $encKey = JWKFactory::createOctKey(128, ['alg' => 'A128GCM', 'use' => 'enc']);
        $sigMgr = new AlgorithmManager([new HS256()]);
        $encMgr = new AlgorithmManager([new Dir(), new A128GCM()]);
        $inner = (new JwsCompact())->serialize(
            (new JWSBuilder($sigMgr))->withPayload('p')->addSignature($sigKey, ['alg' => 'HS256'])->build()
        );
        $jwe = (new JWEBuilder($encMgr))
            ->create()
            ->withPayload($inner)
            ->withSharedProtectedHeader(['alg' => 'dir', 'enc' => 'A128GCM', 'cty' => 'text'])
            ->addRecipient($encKey)
            ->build();
        $token = (new JweCompact())->serialize($jwe);
        $loader = new NestedTokenLoader(
            new JWELoader(new JWESerializerManager([new JweCompact()]), new JWEDecrypter($encMgr), null),
            new JWSLoader(new JWSSerializerManager([new JwsCompact()]), new JWSVerifier($sigMgr), null)
        );
        $this->expectException(InvalidArgumentException::class);
        $loader->load($token, new JWKSet([$encKey]), new JWKSet([$sigKey]));
    }
}
