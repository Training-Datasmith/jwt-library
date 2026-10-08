<?php

declare(strict_types=1);

namespace Jose\Tests\Encryption;

use InvalidArgumentException;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128CBCHS256;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128GCM;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256GCM;
use Jose\Component\Encryption\Algorithm\KeyEncryption\A128KW;
use Jose\Component\Encryption\Algorithm\KeyEncryption\Dir;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\JWELoader;
use Jose\Component\Encryption\Serializer\CompactSerializer;
use Jose\Component\Encryption\Serializer\JSONFlattenedSerializer;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use Jose\Component\KeyManagement\JWKFactory;
use LogicException;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class JWERoundTripTest extends TestCase
{
    public function testDirA128GcmCompact(): void
    {
        $algs = [new Dir(), new A128GCM()];
        $key = JWKFactory::createOctKey(128, ['alg' => 'A128GCM', 'use' => 'enc']);
        $jwe = $this->build($algs, $key, ['alg' => 'dir', 'enc' => 'A128GCM'], 'secret');
        $token = (new CompactSerializer())->serialize($jwe);
        $loaded = (new CompactSerializer())->unserialize($token);
        $dec = new JWEDecrypter(new AlgorithmManager($algs));
        self::assertTrue($dec->decryptUsingKey($loaded, $key, 0));
        self::assertSame('secret', $loaded->getPayload());
        $tag = $loaded->getTag() ?? '';
        $tag = chr(ord($tag[0]) ^ 0x01) . substr($tag, 1);
        $loaded = new \Jose\Component\Encryption\JWE(
            $loaded->getCiphertext(),
            $loaded->getIV() ?? '',
            $tag,
            $loaded->getAAD(),
            $loaded->getSharedHeader(),
            $loaded->getSharedProtectedHeader(),
            $loaded->getEncodedSharedProtectedHeader(),
            $loaded->getRecipients()
        );
        self::assertFalse($dec->decryptUsingKey($loaded, $key, 0));
    }

    public function testCreateResetsContentEncryptionAlgorithm(): void
    {
        $algs = [new Dir(), new A128GCM(), new A128CBCHS256()];
        $k1 = JWKFactory::createOctKey(128, ['alg' => 'A128GCM', 'use' => 'enc']);
        $k2 = JWKFactory::createOctKey(256, ['alg' => 'A128CBC-HS256', 'use' => 'enc']);
        $partial = (new JWEBuilder(new AlgorithmManager($algs)))
            ->create()
            ->withPayload('one')
            ->withSharedProtectedHeader(['alg' => 'dir', 'enc' => 'A128GCM'])
            ->addRecipient($k1);
        $jwe = $partial->create()
            ->withPayload('two')
            ->withSharedProtectedHeader(['alg' => 'dir', 'enc' => 'A128CBC-HS256'])
            ->addRecipient($k2)
            ->build();
        $dec = new JWEDecrypter(new AlgorithmManager($algs));
        self::assertTrue($dec->decryptUsingKey($jwe, $k2, 0));
        self::assertSame('two', $jwe->getPayload());
    }

    public function testAadTamperFailsDecryption(): void
    {
        $algs = [new Dir(), new A128CBCHS256()];
        $key = JWKFactory::createOctKey(256, ['alg' => 'A128CBC-HS256', 'use' => 'enc']);
        $jwe = (new JWEBuilder(new AlgorithmManager($algs)))
            ->create()
            ->withPayload('payload')
            ->withSharedProtectedHeader(['alg' => 'dir', 'enc' => 'A128CBC-HS256'])
            ->withAAD('original-aad')
            ->addRecipient($key)
            ->build();
        $json = (new JSONFlattenedSerializer())->serialize($jwe);
        $data = JsonConverter::decode($json);
        self::assertIsArray($data);
        $data['aad'] = Base64UrlSafe::encodeUnpadded('tampered-aad');
        $loaded = (new JSONFlattenedSerializer())->unserialize(JsonConverter::encode($data));
        $dec = new JWEDecrypter(new AlgorithmManager($algs));
        self::assertFalse($dec->decryptUsingKey($loaded, $key, 0));
    }

    public function testA128KwAndRsaOaep(): void
    {
        $kek = JWKFactory::createOctKey(128, ['alg' => 'A128KW', 'use' => 'enc']);
        $algs1 = [new A128KW(), new A128GCM()];
        $jwe1 = $this->build($algs1, $kek, ['alg' => 'A128KW', 'enc' => 'A128GCM'], 'kw-plain');
        $dec1 = new JWEDecrypter(new AlgorithmManager($algs1));
        self::assertTrue($dec1->decryptUsingKey($jwe1, $kek, 0));

        $rsa = JWKFactory::createRSAKey(2048, ['alg' => 'RSA-OAEP', 'use' => 'enc']);
        $algs2 = [new RSAOAEP(), new A256GCM()];
        $jwe2 = $this->build($algs2, $rsa, ['alg' => 'RSA-OAEP', 'enc' => 'A256GCM'], 'rsa-plain');
        $dec2 = new JWEDecrypter(new AlgorithmManager($algs2));
        self::assertTrue($dec2->decryptUsingKey($jwe2, $rsa, 0));
        $jweWrong = (new JSONFlattenedSerializer())->unserialize((new JSONFlattenedSerializer())->serialize($jwe2));
        $wrong = JWKFactory::createRSAKey(2048, ['alg' => 'RSA-OAEP', 'use' => 'enc']);
        self::assertFalse($dec2->decryptUsingKey($jweWrong, $wrong, 0));
    }

    public function testBuildWithoutPayloadThrows(): void
    {
        $algs = [new Dir(), new A128GCM()];
        $key = JWKFactory::createOctKey(128, ['alg' => 'A128GCM', 'use' => 'enc']);
        $this->expectException(LogicException::class);
        (new JWEBuilder(new AlgorithmManager($algs)))->create()->addRecipient($key)->build();
    }

    public function testBuildWithoutRecipientThrows(): void
    {
        $algs = [new Dir(), new A128GCM()];
        $this->expectException(LogicException::class);
        (new JWEBuilder(new AlgorithmManager($algs)))->create()->withPayload('x')->build();
    }

    public function testCompactRejectsAad(): void
    {
        $algs = [new Dir(), new A128GCM()];
        $key = JWKFactory::createOctKey(128, ['alg' => 'A128GCM', 'use' => 'enc']);
        $jwe = (new JWEBuilder(new AlgorithmManager($algs)))
            ->create()
            ->withPayload('x')
            ->withSharedProtectedHeader(['alg' => 'dir', 'enc' => 'A128GCM'])
            ->withAAD('a')
            ->addRecipient($key)
            ->build();
        $this->expectException(LogicException::class);
        (new CompactSerializer())->serialize($jwe);
    }

    public function testLoaderSuccessAndFailure(): void
    {
        $algs = [new Dir(), new A128GCM()];
        $key = JWKFactory::createOctKey(128, ['alg' => 'A128GCM', 'use' => 'enc']);
        $jwe = (new JWEBuilder(new AlgorithmManager($algs)))
            ->create()
            ->withPayload('x')
            ->withSharedProtectedHeader(['alg' => 'dir', 'enc' => 'A128GCM'])
            ->withAAD('a')
            ->addRecipient($key)
            ->build();
        $token = (new JSONFlattenedSerializer())->serialize($jwe);
        $loader = new JWELoader(new JWESerializerManager([new JSONFlattenedSerializer()]), new JWEDecrypter(new AlgorithmManager($algs)), null);
        $recipient = null;
        self::assertNotNull($loader->loadAndDecryptWithKey($token, $key, $recipient)->getPayload());
        $this->expectException(RuntimeException::class);
        $loader->loadAndDecryptWithKey('bad', $key, $recipient);
    }

    /**
     * @param object[] $algs
     */
    private function build(array $algs, \Jose\Component\Core\JWK $key, array $header, string $payload): \Jose\Component\Encryption\JWE
    {
        return (new JWEBuilder(new AlgorithmManager($algs)))
            ->create()
            ->withPayload($payload)
            ->withSharedProtectedHeader($header)
            ->addRecipient($key)
            ->build();
    }
}
