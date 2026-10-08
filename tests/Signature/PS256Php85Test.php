<?php

declare(strict_types=1);

namespace Jose\Tests\Signature;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\PS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use PHPUnit\Framework\Attributes\RequiresPhp;
use PHPUnit\Framework\TestCase;

#[RequiresPhp('>= 8.5')]
final class PS256Php85Test extends TestCase
{
    public function testPs256RoundTripWithoutChrDeprecation(): void
    {
        $mgr = new AlgorithmManager([new PS256()]);
        $key = JWKFactory::createRSAKey(2048, ['alg' => 'PS256', 'use' => 'sig']);
        $jws = (new JWSBuilder($mgr))->withPayload('php85-ps256')->addSignature($key, ['alg' => 'PS256'])->build();
        $loaded = (new CompactSerializer())->unserialize((new CompactSerializer())->serialize($jws));
        self::assertTrue((new JWSVerifier($mgr))->verifyWithKey($loaded, $key->toPublic(), 0));
    }
}
