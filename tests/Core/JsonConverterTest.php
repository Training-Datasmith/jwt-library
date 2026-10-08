<?php

declare(strict_types=1);

namespace Jose\Tests\Core;

use InvalidArgumentException;
use Jose\Component\Core\Util\JsonConverter;
use PHPUnit\Framework\TestCase;

final class JsonConverterTest extends TestCase
{
    public function testEncodePreservesSlashes(): void
    {
        self::assertSame('{"b":1,"a":"x/y"}', JsonConverter::encode(['b' => 1, 'a' => 'x/y']));
    }

    public function testDecodeRoundTrip(): void
    {
        $data = ['b' => 1, 'a' => 'x/y'];
        self::assertSame($data, JsonConverter::decode(JsonConverter::encode($data)));
    }

    public function testDecodeInvalidJsonThrows(): void
    {
        $this->expectException(InvalidArgumentException::class);
        JsonConverter::decode('{');
    }
}
