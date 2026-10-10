<?php

declare(strict_types=1);

namespace Jose\Tests\Encryption;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128GCM;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHES;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHSSA128KW;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\Serializer\CompactSerializer;
use PHPUnit\Framework\TestCase;

/**
 * Static ECDH-SS decryption needs the recipient private key and sender public key.
 * decryptUsingKey() passes the sender public key as the JWK and the recipient private key as $senderKey
 * (same roles as jwt-framework JWEBuilderSenderKeyTest::decrypt()).
 */
final class JweDecryptUsingKeySenderKeyTest extends TestCase
{
    private const PAYLOAD = 'Live long and prosper.';

    public function testEcdhSsA128KwDecryptUsingKeyWithSenderKey(): void
    {
        $senderPrivateKey = $this->senderPrivateKey();
        $receiverPrivateKey = $this->receiverPrivateKey();
        $receiverPublicKey = $receiverPrivateKey->toPublic();
        $senderPublicKey = $senderPrivateKey->toPublic();

        $algorithms = new AlgorithmManager([new ECDHSSA128KW(), new A128GCM()]);
        $jwe = (new JWEBuilder($algorithms))
            ->create()
            ->withPayload(self::PAYLOAD)
            ->withSharedProtectedHeader([
                'alg' => 'ECDH-SS+A128KW',
                'enc' => 'A128GCM',
            ])
            ->addRecipient($receiverPublicKey)
            ->withSenderKey($senderPrivateKey)
            ->build();

        $loaded = (new CompactSerializer())->unserialize((new CompactSerializer())->serialize($jwe));
        $decrypter = new JWEDecrypter($algorithms);

        self::assertTrue(
            $decrypter->decryptUsingKey($loaded, $senderPublicKey, 0, $receiverPrivateKey)
        );
        self::assertSame(self::PAYLOAD, $loaded->getPayload());

        $withoutRecipientPrivate = (new CompactSerializer())->unserialize((new CompactSerializer())->serialize($jwe));
        self::assertFalse($decrypter->decryptUsingKey($withoutRecipientPrivate, $senderPublicKey, 0));
    }

    public function testEcdhEsDecryptStillSucceedsWhenExtraSenderKeyIsProvided(): void
    {
        $receiverPrivateKey = $this->receiverPrivateKey();
        $senderPublicKey = $this->senderPrivateKey()->toPublic();
        $algorithms = new AlgorithmManager([new ECDHES(), new A128GCM()]);

        $jwe = (new JWEBuilder($algorithms))
            ->create()
            ->withPayload('ecdh-es-plain')
            ->withSharedProtectedHeader([
                'alg' => 'ECDH-ES',
                'enc' => 'A128GCM',
            ])
            ->addRecipient($receiverPrivateKey->toPublic())
            ->build();

        $token = (new CompactSerializer())->serialize($jwe);
        $decrypter = new JWEDecrypter($algorithms);

        $plain = (new CompactSerializer())->unserialize($token);
        self::assertTrue($decrypter->decryptUsingKey($plain, $receiverPrivateKey, 0));
        self::assertSame('ecdh-es-plain', $plain->getPayload());

        $withExtraSender = (new CompactSerializer())->unserialize($token);
        self::assertTrue($decrypter->decryptUsingKey($withExtraSender, $receiverPrivateKey, 0, $senderPublicKey));
        self::assertSame('ecdh-es-plain', $withExtraSender->getPayload());
    }

    private function senderPrivateKey(): JWK
    {
        return new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'OSo9FXcQCqDR6G3INwuMZn9_StSV6eLKn1KQIWufuyA',
            'y' => 'c4v6g44omMI_949wkYtJSG_pOyhyqqqJ7zqqdv5vwGU',
            'd' => 'xBRebaWQIa9DAxChfcOGDnfM39RMILisUxW16XHVN7c',
        ]);
    }

    private function receiverPrivateKey(): JWK
    {
        return new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
            'y' => 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
            'd' => 'VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw',
        ]);
    }
}
