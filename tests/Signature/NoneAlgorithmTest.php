<?php

declare(strict_types=1);

namespace Jose\Tests\Signature;

use InvalidArgumentException;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\None;
use PHPUnit\Framework\TestCase;

final class NoneAlgorithmTest extends TestCase
{
    public function testNoneKeySignAndVerify(): void
    {
        $none = new None();
        $key = JWKFactory::createNoneKey();
        self::assertSame('', $none->sign($key, 'input'));
        self::assertTrue($none->verify($key, 'input', ''));
        self::assertFalse($none->verify($key, 'input', 'x'));
    }

    public function testSignRejectsWrongKeyType(): void
    {
        $none = new None();
        $oct = new \Jose\Component\Core\JWK(['kty' => 'oct', 'k' => 'AA']);
        $this->expectException(InvalidArgumentException::class);
        $none->sign($oct, 'input');
    }
}
