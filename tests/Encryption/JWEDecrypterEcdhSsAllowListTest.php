<?php

declare(strict_types=1);

namespace Jose\Tests\Encryption;

use InvalidArgumentException;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWKSet;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128GCM;
use Jose\Component\Encryption\Algorithm\KeyEncryption\ECDHSSA128KW;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\JWE;
use Jose\Component\Encryption\Serializer\CompactSerializer;
use Jose\Tests\Support\EcdhSsA128KwJweFixture;
use PHPUnit\Framework\TestCase;

final class JWEDecrypterEcdhSsAllowListTest extends TestCase
{
    public function testRejectsEcdhSsTokenWhenAlgorithmManagerExcludesAllEcdhSsVariants(): void
    {
        $loaded = $this->loadFixtureToken();
        $decrypter = new JWEDecrypter(new AlgorithmManager([new A128GCM()]));

        $this->assertDecryptionRejected(
            $decrypter,
            $loaded,
            EcdhSsA128KwJweFixture::senderPrivateKey()->toPublic(),
            EcdhSsA128KwJweFixture::receiverPrivateKey()
        );
    }

    public function testRejectsEcdhSsTokenOnKeySetWhenAlgorithmManagerExcludesAllEcdhSsVariants(): void
    {
        $loaded = $this->loadFixtureToken();
        $decrypter = new JWEDecrypter(new AlgorithmManager([new A128GCM()]));
        $usedKey = null;

        try {
            $result = $decrypter->decryptUsingKeySet(
                $loaded,
                new JWKSet([EcdhSsA128KwJweFixture::senderPrivateKey()->toPublic()]),
                0,
                $usedKey,
                EcdhSsA128KwJweFixture::receiverPrivateKey()
            );
            self::assertFalse($result);
        } catch (InvalidArgumentException) {
            self::addToAssertionCount(1);
        }
    }

    public function testDecryptsWhenEcdhSsA128KwIsAllowed(): void
    {
        $loaded = $this->loadFixtureToken();
        $decrypter = new JWEDecrypter(new AlgorithmManager([new ECDHSSA128KW(), new A128GCM()]));

        self::assertTrue(
            $decrypter->decryptUsingKey(
                $loaded,
                EcdhSsA128KwJweFixture::senderPrivateKey()->toPublic(),
                0,
                EcdhSsA128KwJweFixture::receiverPrivateKey()
            )
        );
        self::assertSame(EcdhSsA128KwJweFixture::PAYLOAD, $loaded->getPayload());
    }

    private function loadFixtureToken(): JWE
    {
        return (new CompactSerializer())->unserialize(EcdhSsA128KwJweFixture::COMPACT_TOKEN);
    }

    private function assertDecryptionRejected(
        JWEDecrypter $decrypter,
        JWE $loaded,
        \Jose\Component\Core\JWK $decryptionJwk,
        \Jose\Component\Core\JWK $senderKey
    ): void {
        try {
            $result = $decrypter->decryptUsingKey($loaded, $decryptionJwk, 0, $senderKey);
            self::assertFalse($result);
        } catch (InvalidArgumentException) {
            self::addToAssertionCount(1);
        }
    }
}
