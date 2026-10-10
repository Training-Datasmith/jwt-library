<?php

declare(strict_types=1);

namespace Jose\Tests\Encryption;

use InvalidArgumentException;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128GCM;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHSSA128KW;
use Jose\Component\Encryption\JWEBuilder;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\Serializer\CompactSerializer;
use PHPUnit\Framework\TestCase;

final class JWEDecrypterEcdhSsAllowListTest extends TestCase
{
    public function testRejectsEcdhSsTokenWhenAlgorithmManagerExcludesAllEcdhSsVariants(): void
    {
        $token = $this->buildEcdhSsA128KwToken();
        $loaded = (new CompactSerializer())->unserialize($token);
        $receiverPrivateKey = $this->receiverPrivateKey();
        $senderPublicKey = $this->senderPrivateKey()->toPublic();

        $decrypter = new JWEDecrypter(new AlgorithmManager([new A128GCM()]));

        $this->expectException(InvalidArgumentException::class);
        $decrypter->decryptUsingKey($loaded, $senderPublicKey, 0, $receiverPrivateKey);
    }

    public function testRejectsEcdhSsTokenOnKeySetWhenAlgorithmManagerExcludesAllEcdhSsVariants(): void
    {
        $token = $this->buildEcdhSsA128KwToken();
        $loaded = (new CompactSerializer())->unserialize($token);
        $receiverPrivateKey = $this->receiverPrivateKey();
        $senderPublicKey = $this->senderPrivateKey()->toPublic();

        $decrypter = new JWEDecrypter(new AlgorithmManager([new A128GCM()]));
        $usedKey = null;

        $this->expectException(InvalidArgumentException::class);
        $decrypter->decryptUsingKeySet(
            $loaded,
            new JWKSet([$senderPublicKey]),
            0,
            $usedKey,
            $receiverPrivateKey
        );
    }

    public function testDecryptsWhenEcdhSsA128KwIsAllowed(): void
    {
        $token = $this->buildEcdhSsA128KwToken();
        $loaded = (new CompactSerializer())->unserialize($token);
        $decrypter = new JWEDecrypter(new AlgorithmManager([new ECDHSSA128KW(), new A128GCM()]));

        self::assertTrue(
            $decrypter->decryptUsingKey(
                $loaded,
                $this->senderPrivateKey()->toPublic(),
                0,
                $this->receiverPrivateKey()
            )
        );
        self::assertSame('allow-list-positive', $loaded->getPayload());
    }

    private function buildEcdhSsA128KwToken(): string
    {
        $algorithms = new AlgorithmManager([new ECDHSSA128KW(), new A128GCM()]);
        $jwe = (new JWEBuilder($algorithms))
            ->create()
            ->withPayload('allow-list-positive')
            ->withSharedProtectedHeader([
                'alg' => 'ECDH-SS+A128KW',
                'enc' => 'A128GCM',
            ])
            ->addRecipient($this->receiverPrivateKey()->toPublic())
            ->withSenderKey($this->senderPrivateKey())
            ->build();

        return (new CompactSerializer())->serialize($jwe);
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
