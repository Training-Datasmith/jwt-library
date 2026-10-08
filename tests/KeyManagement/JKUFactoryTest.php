<?php

declare(strict_types=1);

namespace Jose\Tests\KeyManagement;

use Jose\Component\KeyManagement\JKUFactory;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

final class JKUFactoryTest extends TestCase
{
    public function testLoadFromUrl(): void
    {
        $client = new MockHttpClient([
            new MockResponse('{"keys":[{"kty":"oct","k":"aa","kid":"one"}]}', ['http_code' => 200]),
        ]);
        $factory = new JKUFactory($client);
        $set = $factory->loadFromUrl('https://keys.test/jwks.json');
        self::assertTrue($set->has('one'));
        self::assertSame('oct', $set->get('one')->get('kty'));
    }

    public function testLoadFromUrlHttpError(): void
    {
        $client = new MockHttpClient([new MockResponse('', ['http_code' => 404])]);
        $factory = new JKUFactory($client);
        $this->expectException(RuntimeException::class);
        $factory->loadFromUrl('https://keys.test/jwks.json');
    }
}
