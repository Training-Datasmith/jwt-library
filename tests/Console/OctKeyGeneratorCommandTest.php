<?php

declare(strict_types=1);

namespace Jose\Tests\Console;

use InvalidArgumentException;
use Jose\Component\Console\OctKeyGeneratorCommand;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Core\Util\JsonConverter;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Application;
use Symfony\Component\Console\Tester\CommandTester;

final class OctKeyGeneratorCommandTest extends TestCase
{
    public function testGenerateOctKey(): void
    {
        $app = new Application();
        $app->add(new OctKeyGeneratorCommand());
        $tester = new CommandTester($app->find('key:generate:oct'));
        self::assertSame(0, $tester->execute(['size' => 256]));
        $data = JsonConverter::decode($tester->getDisplay());
        self::assertIsArray($data);
        self::assertSame('oct', $data['kty']);
        self::assertSame(32, strlen(Base64UrlSafe::decodeNoPadding($data['k'])));
    }

    public function testInvalidSize(): void
    {
        $app = new Application();
        $app->add(new OctKeyGeneratorCommand());
        $tester = new CommandTester($app->find('key:generate:oct'));
        $this->expectException(InvalidArgumentException::class);
        $tester->execute(['size' => 0]);
    }
}
