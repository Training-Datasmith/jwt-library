<?php

declare(strict_types=1);

namespace Jose\Tests\Encryption;

use InvalidArgumentException;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128GCM;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A128KW;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\Serializer\CompactSerializer;
use Jose\Component\Encryption\Serializer\JSONGeneralSerializer;
use Jose\Component\KeyManagement\JWKFactory;
use PHPUnit\Framework\TestCase;

final class JWESerializerTest extends TestCase
{
    public function testGeneralTwoRecipients(): void
    {
        $algs = [new A128KW(), new A128GCM()];
        $k1 = JWKFactory::createOctKey(128, ['alg' => 'A128KW', 'kid' => 'a', 'use' => 'enc']);
        $k2 = JWKFactory::createOctKey(128, ['alg' => 'A128KW', 'kid' => 'b', 'use' => 'enc']);
        $jwe = (new JWEBuilder(new AlgorithmManager($algs)))
            ->create()
            ->withPayload('multi')
            ->withSharedProtectedHeader(['alg' => 'A128KW', 'enc' => 'A128GCM'])
            ->addRecipient($k1)
            ->addRecipient($k2)
            ->build();
        $ser = new JSONGeneralSerializer();
        $loaded = $ser->unserialize($ser->serialize($jwe));
        $dec = new JWEDecrypter(new AlgorithmManager($algs));
        self::assertTrue($dec->decryptUsingKey($loaded, $k2, 1));
        self::assertSame('multi', $loaded->getPayload());
    }

    public function testCompactInvalidSegmentCount(): void
    {
        $this->expectException(InvalidArgumentException::class);
        (new CompactSerializer())->unserialize('a.b.c');
    }
}
