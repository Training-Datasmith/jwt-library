<?php

declare(strict_types=1);

namespace Jose\Tests\Signature;

use Exception;
use InvalidArgumentException;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\EdDSA;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\HS384;
use Jose\Component\Signature\Algorithm\HS512;
use Jose\Component\Signature\Algorithm\PS256;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSLoader;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use Jose\Component\Signature\Serializer\JSONGeneralSerializer;
use LogicException;
use PHPUnit\Framework\TestCase;

final class JWSRoundTripTest extends TestCase
{
    public function testHs256RoundTripAndTamper(): void
    {
        $mgr = new AlgorithmManager([new HS256()]);
        $key = JWKFactory::createOctKey(256, ['alg' => 'HS256', 'use' => 'sig']);
        $jws = (new JWSBuilder($mgr))->withPayload('hello')->addSignature($key, ['alg' => 'HS256'])->build();
        $token = (new CompactSerializer())->serialize($jws);
        $loaded = (new CompactSerializer())->unserialize($token);
        self::assertTrue((new JWSVerifier($mgr))->verifyWithKey($loaded, $key, 0));
        $parts = explode('.', $token);
        $sigBytes = Base64UrlSafe::decodeNoPadding($parts[2]);
        $sigBytes = chr(ord($sigBytes[0]) ^ 0x01) . substr($sigBytes, 1);
        $parts[2] = Base64UrlSafe::encodeUnpadded($sigBytes);
        $tampered = (new CompactSerializer())->unserialize(implode('.', $parts));
        self::assertFalse((new JWSVerifier($mgr))->verifyWithKey($tampered, $key, 0));
    }

    public function testRfc7515AppendixA1(): void
    {
        $token = 'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
        $key = new JWK(['kty' => 'oct', 'k' => 'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow']);
        $jws = (new CompactSerializer())->unserialize($token);
        self::assertTrue((new JWSVerifier(new AlgorithmManager([new HS256()])))->verifyWithKey($jws, $key, 0));
        self::assertStringContainsString('"iss":"joe"', $jws->getPayload() ?? '');
    }

    public function testHs256KeyLengthFloor(): void
    {
        $short = new JWK(['kty' => 'oct', 'k' => Base64UrlSafe::encodeUnpadded(str_repeat('a', 31))]);
        $this->expectException(InvalidArgumentException::class);
        (new HS256())->hash($short, 'x');
    }

    public function testHs384KeyLengthFloor(): void
    {
        $short = new JWK(['kty' => 'oct', 'k' => Base64UrlSafe::encodeUnpadded(str_repeat('a', 47))]);
        $this->expectException(InvalidArgumentException::class);
        (new HS384())->hash($short, 'x');
    }

    public function testHs512KeyLengthFloor(): void
    {
        $short = new JWK(['kty' => 'oct', 'k' => Base64UrlSafe::encodeUnpadded(str_repeat('a', 63))]);
        $this->expectException(InvalidArgumentException::class);
        (new HS512())->hash($short, 'x');
    }

    public function testAsymmetricAlgorithms(): void
    {
        $this->roundTrip(new RS256(), JWKFactory::createRSAKey(2048, ['alg' => 'RS256', 'use' => 'sig']));
        $this->roundTrip(new PS256(), JWKFactory::createRSAKey(2048, ['alg' => 'PS256', 'use' => 'sig']));
        $this->roundTrip(new ES256(), JWKFactory::createECKey('P-256', ['alg' => 'ES256', 'use' => 'sig']));
        $this->roundTrip(new EdDSA(), JWKFactory::createOKPKey('Ed25519', ['alg' => 'EdDSA', 'use' => 'sig']));
    }

    public function testDetachedPayload(): void
    {
        $mgr = new AlgorithmManager([new HS256()]);
        $key = JWKFactory::createOctKey(256, ['alg' => 'HS256', 'use' => 'sig']);
        $jws = (new JWSBuilder($mgr))->withPayload('abc', true)->addSignature($key, ['alg' => 'HS256'])->build();
        $token = (new CompactSerializer())->serialize($jws);
        self::assertSame('', explode('.', $token)[1]);
        $loaded = (new CompactSerializer())->unserialize($token);
        $verifier = new JWSVerifier($mgr);
        try {
            $verifier->verifyWithKey($loaded, $key, 0);
            self::fail('detached payload requires explicit payload');
        } catch (InvalidArgumentException) {
        }
        self::assertTrue($verifier->verifyWithKey($loaded, $key, 0, 'abc'));
        self::assertFalse($verifier->verifyWithKey($loaded, $key, 0, 'zzz'));
    }

    public function testUnencodedPayloadRequiresCrit(): void
    {
        $mgr = new AlgorithmManager([new HS256()]);
        $key = JWKFactory::createOctKey(256, ['alg' => 'HS256', 'use' => 'sig']);
        $this->expectException(LogicException::class);
        (new JWSBuilder($mgr))->withPayload('plain')->addSignature($key, ['alg' => 'HS256', 'b64' => false]);
    }

    public function testLoaderSuccessAndFailure(): void
    {
        $mgr = new AlgorithmManager([new HS256()]);
        $key = JWKFactory::createOctKey(256, ['alg' => 'HS256', 'use' => 'sig']);
        $token = (new CompactSerializer())->serialize(
            (new JWSBuilder($mgr))->withPayload('ok')->addSignature($key, ['alg' => 'HS256'])->build()
        );
        $loader = new JWSLoader(new JWSSerializerManager([new CompactSerializer()]), new JWSVerifier($mgr), null);
        $idx = null;
        self::assertSame('ok', $loader->loadAndVerifyWithKey($token, $key, $idx)->getPayload());
        self::assertSame(0, $idx);
        $this->expectException(Exception::class);
        $loader->loadAndVerifyWithKey('not.a.token', $key, $idx);
    }

    public function testKeyUseRejection(): void
    {
        $mgr = new AlgorithmManager([new HS256()]);
        $bad = JWKFactory::createOctKey(256, ['alg' => 'HS256', 'use' => 'enc']);
        $this->expectException(InvalidArgumentException::class);
        (new JWSBuilder($mgr))->withPayload('x')->addSignature($bad, ['alg' => 'HS256'])->build();
    }

    private function roundTrip(object $alg, JWK $private): void
    {
        $mgr = new AlgorithmManager([$alg]);
        $jws = (new JWSBuilder($mgr))->withPayload('hello ' . $alg->name())->addSignature($private, ['alg' => $alg->name()])->build();
        $loaded = (new CompactSerializer())->unserialize((new CompactSerializer())->serialize($jws));
        self::assertTrue((new JWSVerifier($mgr))->verifyWithKey($loaded, $private->toPublic(), 0));
    }
}
