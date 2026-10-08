<?php

declare(strict_types=1);

namespace Jose\Tests\Core;

use Brick\Math\BigInteger;
use Jose\Component\Core\Util\Ecc\NistCurve;
use PHPUnit\Framework\TestCase;

final class CurveMulTest extends TestCase
{
    public function testP256GeneratorTimesTwo(): void
    {
        $curve = NistCurve::curve256();
        $g = $curve->getGenerator();
        $twoG = $curve->mul($g, BigInteger::of(2));

        $expectedX = BigInteger::fromBase('7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978', 16);
        $expectedY = BigInteger::fromBase('7775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1', 16);

        self::assertTrue($twoG->getX()->isEqualTo($expectedX));
        self::assertTrue($twoG->getY()->isEqualTo($expectedY));
    }
}
