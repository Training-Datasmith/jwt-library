<?php

declare (strict_types=1);
namespace Jose\Component\Core\Util\Ecc;

use Brick\Math\Big_Integer;
use const STR_PAD_LEFT;
use function strlen;
/**
 * Copyright (C) 2012 Matyas Danter.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
 * documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
 * WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
/**
 * @internal
 */
final readonly class Point
{
    private function __construct(private Big_Integer $x, private Big_Integer $y, private Big_Integer $order, private bool $infinity = false)
    {
    }
    public static function create(Big_Integer $x, Big_Integer $y, ?Big_Integer $order = null): self
    {
        return new self($x, $y, $order ?? Big_Integer::zero());
    }
    public static function infinity(): self
    {
        $zero = Big_Integer::zero();
        return new self($zero, $zero, $zero, true);
    }
    public function is_infinity(): bool
    {
        return $this->infinity;
    }
    public function get_order(): Big_Integer
    {
        return $this->order;
    }
    public function get_x(): Big_Integer
    {
        return $this->x;
    }
    public function get_y(): Big_Integer
    {
        return $this->y;
    }
    public static function cswap(self $a, self $b, int $cond): void
    {
        self::cswap_big_integer($a->x, $b->x, $cond);
        self::cswap_big_integer($a->y, $b->y, $cond);
        self::cswap_big_integer($a->order, $b->order, $cond);
        self::cswap_boolean($a->infinity, $b->infinity, $cond);
    }
    private static function cswap_boolean(bool &$a, bool &$b, int $cond): void
    {
        $sa = Big_Integer::of((int) $a);
        $sb = Big_Integer::of((int) $b);
        self::cswap_big_integer($sa, $sb, $cond);
        $a = (bool) $sa->to_base(10);
        $b = (bool) $sb->to_base(10);
    }
    private static function cswap_big_integer(Big_Integer &$sa, Big_Integer &$sb, int $cond): void
    {
        $size = max(strlen($sa->to_base(2)), strlen($sb->to_base(2)));
        $mask = (string) (1 - $cond);
        $mask = str_pad('', $size, $mask, STR_PAD_LEFT);
        $mask = Big_Integer::from_base($mask, 2);
        $ta_a = $sa->and($mask);
        $ta_b = $sb->and($mask);
        $sa = $sa->xor($sb)->xor($ta_b);
        $sb = $sa->xor($sb)->xor($ta_a);
        $sa = $sa->xor($sb)->xor($ta_b);
    }
}