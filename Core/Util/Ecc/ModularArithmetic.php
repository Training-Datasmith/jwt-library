<?php

declare (strict_types=1);
namespace Jose\Component\Core\Util\Ecc;

use Brick\Math\Big_Integer;
/**
 * @internal
 */
final readonly class Modular_Arithmetic
{
    public static function sub(Big_Integer $minuend, Big_Integer $subtrahend, Big_Integer $modulus): Big_Integer
    {
        return $minuend->minus($subtrahend)->mod($modulus);
    }
    public static function mul(Big_Integer $multiplier, Big_Integer $muliplicand, Big_Integer $modulus): Big_Integer
    {
        return $multiplier->multiplied_by($muliplicand)->mod($modulus);
    }
    public static function div(Big_Integer $dividend, Big_Integer $divisor, Big_Integer $modulus): Big_Integer
    {
        return self::mul($dividend, Math::inverse_mod($divisor, $modulus), $modulus);
    }
}