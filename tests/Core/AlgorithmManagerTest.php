<?php

declare(strict_types=1);

namespace Jose\Tests\Core;

use InvalidArgumentException;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\AlgorithmManagerFactory;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\HS384;
use PHPUnit\Framework\TestCase;

final class AlgorithmManagerTest extends TestCase
{
    public function testGetHasList(): void
    {
        $hs = new HS256();
        $mgr = new AlgorithmManager([$hs]);
        self::assertTrue($mgr->has('HS256'));
        self::assertSame($hs, $mgr->get('HS256'));
        self::assertSame(['HS256'], $mgr->list());
    }

    public function testGetUnknownThrows(): void
    {
        $mgr = new AlgorithmManager([]);
        $this->expectException(InvalidArgumentException::class);
        $mgr->get('nope');
    }

    public function testAddReplacesSameName(): void
    {
        $mgr = new AlgorithmManager([new HS256()]);
        $hs384 = new HS384();
        $mgr->add($hs384);
        $mgr->add(new HS256());
        self::assertInstanceOf(HS256::class, $mgr->get('HS256'));
    }

    public function testFactory(): void
    {
        $factory = new AlgorithmManagerFactory([new HS256()]);
        $mgr = $factory->create(['HS256']);
        self::assertTrue($mgr->has('HS256'));
        $this->expectException(InvalidArgumentException::class);
        $factory->create(['missing']);
    }
}
