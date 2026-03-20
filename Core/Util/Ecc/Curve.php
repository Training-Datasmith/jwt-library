<?php

declare (strict_types=1);
namespace Jose\Component\Core\Util\Ecc;

use Brick\Math\Big_Integer;
use Override;
use RuntimeException;
use const STR_PAD_LEFT;
use Stringable;
/**
 * @internal
 */
final readonly class Curve implements Stringable
{
    public function __construct(private int $size, private Big_Integer $prime, private Big_Integer $a, private Big_Integer $b, private Point $generator)
    {
    }
    #[Override]
    public function __toString(): string
    {
        return 'curve(' . Math::to_string($this->get_a()) . ', ' . Math::to_string($this->get_b()) . ', ' . Math::to_string($this->get_prime()) . ')';
    }
    public function get_a(): Big_Integer
    {
        return $this->a;
    }
    public function get_b(): Big_Integer
    {
        return $this->b;
    }
    public function get_prime(): Big_Integer
    {
        return $this->prime;
    }
    public function get_size(): int
    {
        return $this->size;
    }
    public function get_point(Big_Integer $x, Big_Integer $y, ?Big_Integer $order = null): Point
    {
        if (!$this->contains($x, $y)) {
            throw new RuntimeException('Curve ' . $this->__toString() . ' does not contain point (' . Math::to_string($x) . ', ' . Math::to_string($y) . ')');
        }
        $point = Point::create($x, $y, $order);
        if ($order !== null) {
            $mul = $this->mul($point, $order);
            if (!$mul->is_infinity()) {
                throw new RuntimeException('SELF * ORDER MUST EQUAL INFINITY.');
            }
        }
        return $point;
    }
    public function get_public_key_from(Big_Integer $x, Big_Integer $y): Public_Key
    {
        $zero = Big_Integer::zero();
        if ($x->compare_to($zero) < 0 || $y->compare_to($zero) < 0 || $this->generator->get_order()->compare_to($x) <= 0 || $this->generator->get_order()->compare_to($y) <= 0) {
            throw new RuntimeException('Generator point has x and y out of range.');
        }
        $point = $this->get_point($x, $y);
        return new Public_Key($point);
    }
    public function contains(Big_Integer $x, Big_Integer $y): bool
    {
        return Math::equals(Modular_Arithmetic::sub($y->power(2), Math::add(Math::add($x->power(3), $this->get_a()->multiplied_by($x)), $this->get_b()), $this->get_prime()), Big_Integer::zero());
    }
    public function add(Point $one, Point $two): Point
    {
        if ($two->is_infinity()) {
            return clone $one;
        }
        if ($one->is_infinity()) {
            return clone $two;
        }
        if ($two->get_x()->is_equal_to($one->get_x())) {
            if ($two->get_y()->is_equal_to($one->get_y())) {
                return $this->get_double($one);
            }
            return Point::infinity();
        }
        $slope = Modular_Arithmetic::div($two->get_y()->minus($one->get_y()), $two->get_x()->minus($one->get_x()), $this->get_prime());
        $x_r = Modular_Arithmetic::sub($slope->power(2)->minus($one->get_x()), $two->get_x(), $this->get_prime());
        $y_r = Modular_Arithmetic::sub($slope->multiplied_by($one->get_x()->minus($x_r)), $one->get_y(), $this->get_prime());
        return $this->get_point($x_r, $y_r, $one->get_order());
    }
    public function mul(Point $one, Big_Integer $n): Point
    {
        if ($one->is_infinity()) {
            return Point::infinity();
        }
        /** @var BigInteger $zero */
        $zero = Big_Integer::zero();
        if ($one->get_order()->compare_to($zero) > 0) {
            $n = $n->mod($one->get_order());
        }
        if ($n->is_equal_to($zero)) {
            return Point::infinity();
        }
        /** @var Point[] $r */
        $r = [Point::infinity(), clone $one];
        $k = $this->get_size();
        $n1 = str_pad(Math::base_convert(Math::to_string($n), 10, 2), $k, '0', STR_PAD_LEFT);
        for ($i = 0; $i < $k; ++$i) {
            $j = $n1[$i];
            Point::cswap($r[0], $r[1], $j ^ 1);
            $r[0] = $this->add($r[0], $r[1]);
            $r[1] = $this->get_double($r[1]);
            Point::cswap($r[0], $r[1], $j ^ 1);
        }
        $this->validate($r[0]);
        return $r[0];
    }
    public function cmp(self $other): int
    {
        $equals_a = $this->get_a()->is_equal_to($other->get_a());
        $equals_b = $this->get_b()->is_equal_to($other->get_b());
        $equals_prime = $this->get_prime()->is_equal_to($other->get_prime());
        $equal = $equals_a && $equals_b && $equals_prime;
        return $equal ? 0 : 1;
    }
    public function equals(self $other): bool
    {
        return $this->cmp($other) === 0;
    }
    public function get_double(Point $point): Point
    {
        if ($point->is_infinity()) {
            return Point::infinity();
        }
        $a = $this->get_a();
        $three_x2 = Big_Integer::of(3)->multiplied_by($point->get_x()->power(2));
        $tangent = Modular_Arithmetic::div($three_x2->plus($a), Big_Integer::of(2)->multiplied_by($point->get_y()), $this->get_prime());
        $x3 = Modular_Arithmetic::sub($tangent->power(2), Big_Integer::of(2)->multiplied_by($point->get_x()), $this->get_prime());
        $y3 = Modular_Arithmetic::sub($tangent->multiplied_by($point->get_x()->minus($x3)), $point->get_y(), $this->get_prime());
        return $this->get_point($x3, $y3, $point->get_order());
    }
    public function create_private_key(): Private_Key
    {
        return Private_Key::create($this->generate());
    }
    public function create_public_key(Private_Key $private_key): Public_Key
    {
        $point = $this->mul($this->generator, $private_key->get_secret());
        return new Public_Key($point);
    }
    public function get_generator(): Point
    {
        return $this->generator;
    }
    private function validate(Point $point): void
    {
        if (!$point->is_infinity() && !$this->contains($point->get_x(), $point->get_y())) {
            throw new RuntimeException('Invalid point');
        }
    }
    private function generate(): Big_Integer
    {
        $max = $this->generator->get_order();
        $num_bits = $this->bn_num_bits($max);
        $num_bytes = (int) ceil($num_bits / 8);
        // Generate an integer of size >= $numBits
        $bytes = Big_Integer::random_bits($num_bytes);
        $mask = Big_Integer::of(2)->power($num_bits)->minus(1);
        return $bytes->and($mask);
    }
    /**
     * Returns the number of bits used to store this number. Non-significant upper bits are not counted.
     *
     * @see https://www.openssl.org/docs/crypto/BN_num_bytes.html
     */
    private function bn_num_bits(Big_Integer $x): int
    {
        $zero = Big_Integer::of(0);
        if ($x->is_equal_to($zero)) {
            return 0;
        }
        $log2 = 0;
        while (!$x->is_equal_to($zero)) {
            $x = $x->shifted_right(1);
            ++$log2;
        }
        return $log2;
    }
}