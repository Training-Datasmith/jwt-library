<?php

declare(strict_types=1);

namespace Jose\Tests\Core;

use Jose\Component\Core\Util\Base64UrlSafe;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use RangeException;

final class Base64UrlSafeTest extends TestCase
{
    #[DataProvider('roundTripProvider')]
    public function testEncodeDecodeRoundTrip(string $input): void
    {
        self::assertSame($input, Base64UrlSafe::decode(Base64UrlSafe::encode($input)));
        self::assertSame($input, Base64UrlSafe::decodeNoPadding(Base64UrlSafe::encodeUnpadded($input)));
    }

    public static function roundTripProvider(): array
    {
        return [
            'empty' => [''],
            'a' => ['a'],
            'ab' => ['ab'],
            'abc' => ['abc'],
            'binary' => ["\x00\xff"],
        ];
    }

    public function testEncodePaddingVariants(): void
    {
        self::assertSame('aGVsbG8=', Base64UrlSafe::encode('hello'));
        self::assertSame('aGVsbG8', Base64UrlSafe::encodeUnpadded('hello'));
    }

    public function testDecodeNoPaddingRejectsPadding(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Base64UrlSafe::decodeNoPadding('aGVsbG8=');
    }

    public function testDecodeRejectsInvalidAlphabet(): void
    {
        $this->expectException(RangeException::class);
        Base64UrlSafe::decode('!!!');
    }
}
