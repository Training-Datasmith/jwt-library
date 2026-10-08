<?php

declare(strict_types=1);

namespace Jose\Tests\KeyManagement;

use InvalidArgumentException;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\KeyManagement\JWKFactory;
use PHPUnit\Framework\TestCase;

final class JWKFactoryTest extends TestCase
{
    public function testCreateOctKey(): void
    {
        $jwk = JWKFactory::createOctKey(256);
        self::assertSame('oct', $jwk->get('kty'));
        self::assertSame(32, strlen(Base64UrlSafe::decodeNoPadding($jwk->get('k'))));
        $this->expectException(InvalidArgumentException::class);
        JWKFactory::createOctKey(7);
    }

    public function testCreateRsaKey(): void
    {
        $jwk = JWKFactory::createRSAKey(2048, ['alg' => 'RS256', 'use' => 'sig']);
        self::assertSame('RSA', $jwk->get('kty'));
        self::assertTrue($jwk->has('d'));
        self::assertFalse($jwk->toPublic()->has('d'));
        $this->expectException(InvalidArgumentException::class);
        JWKFactory::createRSAKey(256);
    }

    public function testCreateEcAndOkp(): void
    {
        $ec = JWKFactory::createECKey('P-256', ['alg' => 'ES256', 'use' => 'sig']);
        self::assertSame('EC', $ec->get('kty'));
        self::assertSame('P-256', $ec->get('crv'));
        $ed = JWKFactory::createOKPKey('Ed25519', ['alg' => 'EdDSA', 'use' => 'sig']);
        self::assertSame('Ed25519', $ed->get('crv'));
        self::assertFalse($ed->toPublic()->has('d'));
        $x = JWKFactory::createOKPKey('X25519');
        self::assertSame('X25519', $x->get('crv'));
    }

    public function testCreateNoneAndSecret(): void
    {
        $none = JWKFactory::createNoneKey();
        self::assertSame('none', $none->get('kty'));
        self::assertSame('none', $none->get('alg'));
        $oct = JWKFactory::createFromSecret('secret');
        self::assertSame('secret', Base64UrlSafe::decodeNoPadding($oct->get('k')));
    }

    public function testCreateFromValues(): void
    {
        self::assertInstanceOf(JWKSet::class, JWKFactory::createFromValues(['keys' => [['kty' => 'oct', 'k' => 'AA']]]));
        self::assertInstanceOf(JWK::class, JWKFactory::createFromValues(['kty' => 'oct', 'k' => 'AA']));
    }

    public function testCreateFromCertificate(): void
    {
        $res = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($res);
        $csr = openssl_csr_new(['CN' => 'test'], $res);
        self::assertNotFalse($csr);
        $cert = openssl_csr_sign($csr, null, $res, 1);
        self::assertNotFalse($cert);
        openssl_x509_export($cert, $pem);
        $jwk = JWKFactory::createFromCertificate($pem);
        self::assertSame('RSA', $jwk->get('kty'));
        self::assertFalse($jwk->has('d'));
    }
}
