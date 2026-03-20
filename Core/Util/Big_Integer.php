<?php

declare (strict_types=1);
namespace Jose\Component\Core\Util;

use Brick\Math\Big_Integer as BrickBigInteger;
use function chr;
use InvalidArgumentException;
use function strlen;
/**
 * @internal
 */
final readonly class Big_Integer
{
    private function __construct(private Brick_Big_Integer $value)
    {
    }
    public static function create_from_binary_string(string $value): self
    {
        $res = unpack('H*', $value);
        if ($res === false) {
            throw new InvalidArgumentException('Unable to convert the value');
        }
        $data = current($res);
        return new self(Brick_Big_Integer::from_base($data, 16));
    }
    public static function create_from_decimal(int $value): self
    {
        return new self(Brick_Big_Integer::of($value));
    }
    public static function create_from_big_integer(Brick_Big_Integer $value): self
    {
        return new self($value);
    }
    /**
     * Converts a BigInteger to a binary string.
     */
    public function to_bytes(): string
    {
        if ($this->value->is_equal_to(Brick_Big_Integer::zero())) {
            return '';
        }
        $temp = $this->value->to_base(16);
        $temp = 0 !== (strlen($temp) & 1) ? '0' . $temp : $temp;
        $temp = hex2bin($temp);
        if ($temp === false) {
            throw new InvalidArgumentException('Unable to convert the value into bytes');
        }
        return ltrim($temp, chr(0));
    }
    /**
     * Adds two BigIntegers.
     */
    public function add(self $y): self
    {
        $value = $this->value->plus($y->value);
        return new self($value);
    }
    /**
     * Subtracts two BigIntegers.
     */
    public function subtract(self $y): self
    {
        $value = $this->value->minus($y->value);
        return new self($value);
    }
    /**
     * Multiplies two BigIntegers.
     */
    public function multiply(self $x): self
    {
        $value = $this->value->multiplied_by($x->value);
        return new self($value);
    }
    /**
     * Divides two BigIntegers.
     */
    public function divide(self $x): self
    {
        $value = $this->value->divided_by($x->value);
        return new self($value);
    }
    /**
     * Performs modular exponentiation.
     */
    public function mod_pow(self $e, self $n): self
    {
        $value = $this->value->mod_pow($e->value, $n->value);
        return new self($value);
    }
    /**
     * Performs modular exponentiation.
     */
    public function mod(self $d): self
    {
        $value = $this->value->mod($d->value);
        return new self($value);
    }
    public function mod_inverse(self $m): self
    {
        return new self($this->value->mod_inverse($m->value));
    }
    /**
     * Compares two numbers.
     */
    public function compare(self $y): int
    {
        return $this->value->compare_to($y->value);
    }
    public function equals(self $y): bool
    {
        return $this->value->is_equal_to($y->value);
    }
    public static function random(self $y): self
    {
        return new self(Brick_Big_Integer::random_range(0, $y->value));
    }
    public function gcd(self $y): self
    {
        return new self($this->value->gcd($y->value));
    }
    public function lower_than(self $y): bool
    {
        return $this->value->is_less_than($y->value);
    }
    public function is_even(): bool
    {
        return $this->value->is_even();
    }
    public function get(): Brick_Big_Integer
    {
        return $this->value;
    }
}