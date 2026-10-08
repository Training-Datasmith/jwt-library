<?php

declare(strict_types=1);

namespace Jose\Tests\Signature;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\JSONFlattenedSerializer;
use Jose\Component\Signature\Serializer\JSONGeneralSerializer;
use LogicException;
use PHPUnit\Framework\TestCase;

final class JWSSerializerTest extends TestCase
{
    private function hsKeyAndMgr(): array
    {
        return [JWKFactory::createOctKey(256, ['alg' => 'HS256', 'use' => 'sig']), new AlgorithmManager([new HS256()])];
    }

    public function testJsonGeneralDetachedRoundTrip(): void
    {
        [$key, $mgr] = $this->hsKeyAndMgr();
        $jws = (new JWSBuilder($mgr))->withPayload('abc', true)->addSignature($key, ['alg' => 'HS256'])->build();
        $ser = new JSONGeneralSerializer();
        $json = $ser->serialize($jws);
        self::assertStringNotContainsString('"payload"', $json);
        $loaded = $ser->unserialize($json);
        self::assertTrue($loaded->isPayloadDetached());
        self::assertStringNotContainsString('"payload"', $ser->serialize($loaded));
    }

    public function testJsonGeneralExplicitNullPayloadNotDetached(): void
    {
        $ser = new JSONGeneralSerializer();
        $input = '{"payload":null,"signatures":[{"signature":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","protected":"eyJhbGciOiJIUzI1NiJ9"}]}';
        $loaded = $ser->unserialize($input);
        self::assertFalse($loaded->isPayloadDetached());
    }

    public function testJsonFlattenedDetached(): void
    {
        [$key, $mgr] = $this->hsKeyAndMgr();
        $jws = (new JWSBuilder($mgr))->withPayload('abc', true)->addSignature($key, ['alg' => 'HS256'])->build();
        $flat = new JSONFlattenedSerializer();
        $loaded = $flat->unserialize($flat->serialize($jws));
        self::assertTrue($loaded->isPayloadDetached());
    }

    public function testCompactRejectsUnprotectedHeader(): void
    {
        [$key, $mgr] = $this->hsKeyAndMgr();
        $jws = (new JWSBuilder($mgr))
            ->withPayload('x')
            ->addSignature($key, ['alg' => 'HS256'], ['kid' => '1'])
            ->build();
        $this->expectException(LogicException::class);
        (new \Jose\Component\Signature\Serializer\CompactSerializer())->serialize($jws);
    }
}
