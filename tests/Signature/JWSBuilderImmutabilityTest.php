<?php

declare(strict_types=1);

namespace Jose\Tests\Signature;

use InvalidArgumentException;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use PHPUnit\Framework\TestCase;

final class JWSBuilderImmutabilityTest extends TestCase
{
    public function testFailedAddSignatureDoesNotContaminateEncodingState(): void
    {
        $mgr = new AlgorithmManager([new HS256()]);
        $key = JWKFactory::createOctKey(256, ['alg' => 'HS256', 'use' => 'sig']);
        $builder = (new JWSBuilder($mgr))->withPayload('hello');

        try {
            $builder->addSignature($key, ['alg' => 'HS256', 'kid' => '1'], ['kid' => '2']);
            self::fail('expected duplicate header');
        } catch (InvalidArgumentException) {
        }

        $jws = $builder
            ->addSignature($key, ['alg' => 'HS256', 'b64' => false, 'crit' => ['b64']])
            ->build();

        self::assertSame('hello', $jws->getEncodedPayload());
        self::assertTrue((new JWSVerifier($mgr))->verifyWithKey($jws, $key, 0));
    }

    public function testWithPayloadReturnsDistinctBuilders(): void
    {
        $mgr = new AlgorithmManager([new HS256()]);
        $key = JWKFactory::createOctKey(256, ['alg' => 'HS256', 'use' => 'sig']);
        $a = (new JWSBuilder($mgr))->withPayload('one');
        $b = $a->withPayload('two');
        $jwsA = $a->addSignature($key, ['alg' => 'HS256'])->build();
        $jwsB = $b->addSignature($key, ['alg' => 'HS256'])->build();
        self::assertSame('one', $jwsA->getPayload());
        self::assertSame('two', $jwsB->getPayload());
    }

    public function testForeignPayloadEncodingOnReturnedClone(): void
    {
        $mgr = new AlgorithmManager([new HS256()]);
        $key = JWKFactory::createOctKey(256, ['alg' => 'HS256', 'use' => 'sig']);
        $builder = (new JWSBuilder($mgr))
            ->withPayload('x')
            ->addSignature($key, ['alg' => 'HS256', 'b64' => false, 'crit' => ['b64']]);
        $this->expectException(InvalidArgumentException::class);
        $builder->addSignature($key, ['alg' => 'HS256']);
    }
}
