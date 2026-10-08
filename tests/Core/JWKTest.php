<?php

declare(strict_types=1);

namespace Jose\Tests\Core;

use InvalidArgumentException;
use Jose\Component\Core\JWK;
use PHPUnit\Framework\TestCase;

final class JWKTest extends TestCase
{
    public function testConstructorRequiresKty(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new JWK([]);
    }

    public function testGetHas(): void
    {
        $jwk = new JWK(['kty' => 'oct', 'k' => 'AA']);
        self::assertTrue($jwk->has('k'));
        self::assertFalse($jwk->has('kid'));
        self::assertSame('AA', $jwk->get('k'));
    }

    public function testGetMissingThrows(): void
    {
        $jwk = new JWK(['kty' => 'oct']);
        $this->expectException(InvalidArgumentException::class);
        $jwk->get('k');
    }

    public function testCreateFromJsonObject(): void
    {
        $jwk = JWK::createFromJson('{"kty":"oct","k":"AA"}');
        self::assertSame(['kty' => 'oct', 'k' => 'AA'], $jwk->jsonSerialize());
    }

    public function testCreateFromJsonRejectsNonObject(): void
    {
        $this->expectException(InvalidArgumentException::class);
        JWK::createFromJson('[]');
    }

    public function testThumbprintRfc7638Rsa(): void
    {
        $n = '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw';
        $jwk = new JWK(['kty' => 'RSA', 'n' => $n, 'e' => 'AQAB', 'alg' => 'RS256', 'kid' => 'x', 'd' => 'secret']);
        self::assertSame('NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs', $jwk->thumbprint('sha256'));
    }

    public function testThumbprintUnknownHash(): void
    {
        $jwk = new JWK(['kty' => 'oct', 'k' => 'AA']);
        $this->expectException(InvalidArgumentException::class);
        $jwk->thumbprint('not-a-hash');
    }

    public function testToPublicStripsPrivateRsaMembers(): void
    {
        $jwk = new JWK(['kty' => 'RSA', 'n' => 'AA', 'e' => 'AQAB', 'd' => 'BB', 'p' => 'CC']);
        $pub = $jwk->toPublic();
        self::assertFalse($pub->has('d'));
        self::assertFalse($pub->has('p'));
        self::assertTrue($pub->has('n'));
    }
}
