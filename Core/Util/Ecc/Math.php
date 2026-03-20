<?php

declare (strict_types=1);
namespace Jose\Component\Core\Util\Ecc;

use Brick\Math\Big_Integer;
use Jose\Component\Core\Util\Big_Integer as CoreBigInteger;
/**
 * @internal
 */
final readonly class Math
{
    public static function equals(Big_Integer $first, Big_Integer $other): bool
    {
        return $first->is_equal_to($other);
    }
    public static function add(Big_Integer $augend, Big_Integer $addend): Big_Integer
    {
        return $augend->plus($addend);
    }
    public static function to_string(Big_Integer $value): string
    {
        return $value->to_base(10);
    }
    public static function inverse_mod(Big_Integer $a, Big_Integer $m): Big_Integer
    {
        return Core_Big_Integer::create_from_big_integer($a)->mod_inverse(Core_Big_Integer::create_from_big_integer($m))->get();
    }
    public static function base_convert(string $number, int $from, int $to): string
    {
        return Big_Integer::from_base($number, $from)->to_base($to);
    }
}