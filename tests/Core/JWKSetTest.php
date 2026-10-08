<?php

declare(strict_types=1);

namespace Jose\Tests\Core;

use InvalidArgumentException;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\Algorithm\HS256;
use PHPUnit\Framework\TestCase;

final class JWKSetTest extends TestCase
{
    public function testKidIndexing(): void
    {
        $a = new JWK(['kty' => 'oct', 'kid' => 'a', 'k' => 'AA']);
        $b = new JWK(['kty' => 'oct', 'k' => 'BB']);
        $set = new JWKSet([$a, $b]);
        self::assertSame('a', $set->get('a')->get('kid'));
        self::assertCount(2, $set);
    }

    public function testRejectsNonJwk(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new JWKSet([new \stdClass()]);
    }

    public function testWithWithoutImmutable(): void
    {
        $set = new JWKSet([]);
        $key = new JWK(['kty' => 'oct', 'kid' => 'x', 'k' => 'AA']);
        $next = $set->with($key);
        self::assertCount(0, $set);
        self::assertCount(1, $next);
        $removed = $next->without('x');
        self::assertCount(0, $removed);
    }

    public function testGetMissingThrows(): void
    {
        $set = new JWKSet([]);
        $this->expectException(InvalidArgumentException::class);
        $set->get('missing');
    }

    public function testCreateFromJson(): void
    {
        $set = JWKSet::createFromJson('{"keys":[{"kty":"oct","kid":"1","k":"AA"},{"kty":"oct","k":"BB"}]}');
        self::assertCount(2, $set);
    }

    public function testSelectKey(): void
    {
        $hs = new HS256();
        $mgr = new AlgorithmManager([$hs]);
        $sig = new JWK(['kty' => 'oct', 'use' => 'sig', 'alg' => 'HS256', 'kid' => 'a', 'k' => str_repeat('A', 43)]);
        $enc = new JWK(['kty' => 'oct', 'use' => 'enc', 'kid' => 'b', 'k' => 'BB']);
        $set = new JWKSet([$sig, $enc]);
        $found = $set->selectKey('sig', $hs, ['kid' => 'a']);
        self::assertNotNull($found);
        self::assertSame('a', $found->get('kid'));
        self::assertNull($set->selectKey('sig', $hs, ['kid' => 'missing']));
        $this->expectException(InvalidArgumentException::class);
        $set->selectKey('foo');
    }

    public function testJsonSerializeUsesList(): void
    {
        $set = new JWKSet([new JWK(['kty' => 'oct', 'kid' => 'a', 'k' => 'AA'])]);
        $json = $set->jsonSerialize();
        self::assertArrayHasKey('keys', $json);
        self::assertIsList($json['keys']);
    }
}
