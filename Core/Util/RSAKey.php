<?php

declare (strict_types=1);
namespace Jose\Component\Core\Util;

use function array_key_exists;
use function count;
use InvalidArgumentException;
use function is_array;
use Jose\Component\Core\JWK;
use RuntimeException;
use Spomky_Labs\Pki\ASN1\Type\Constructed\Sequence;
use Spomky_Labs\Pki\ASN1\Type\Primitive\Bit_String;
use Spomky_Labs\Pki\ASN1\Type\Primitive\Integer;
use Spomky_Labs\Pki\ASN1\Type\Primitive\Octet_String;
use Spomky_Labs\Pki\Crypto_Encoding\PEM;
use Spomky_Labs\Pki\Crypto_Types\Algorithm_Identifier\Asymmetric\Rsa_Encryption_Algorithm_Identifier;
use Spomky_Labs\Pki\Crypto_Types\Asymmetric\RSA\Rsa_Private_Key;
use Spomky_Labs\Pki\Crypto_Types\Asymmetric\RSA\Rsa_Public_Key;
use function strlen;
/**
 * @internal
 */
final class Rsa_Key
{
    private null|Sequence $sequence = null;
    private readonly array $values;
    private Big_Integer $modulus;
    private int $modulus_length;
    private Big_Integer $public_exponent;
    private ?Big_Integer $private_exponent = null;
    /**
     * @var BigInteger[]
     */
    private array $primes = [];
    /**
     * @var BigInteger[]
     */
    private array $exponents = [];
    private ?Big_Integer $coefficient = null;
    private function __construct(JWK $data)
    {
        $this->values = $data->all();
        $this->populate_big_integers();
    }
    public static function create_from_jwk(JWK $jwk): self
    {
        return new self($jwk);
    }
    public function get_modulus(): Big_Integer
    {
        return $this->modulus;
    }
    public function get_modulus_length(): int
    {
        return $this->modulus_length;
    }
    public function get_exponent(): Big_Integer
    {
        $d = $this->get_private_exponent();
        if ($d !== null) {
            return $d;
        }
        return $this->get_public_exponent();
    }
    public function get_public_exponent(): Big_Integer
    {
        return $this->public_exponent;
    }
    public function get_private_exponent(): ?Big_Integer
    {
        return $this->private_exponent;
    }
    /**
     * @return BigInteger[]
     */
    public function get_primes(): array
    {
        return $this->primes;
    }
    /**
     * @return BigInteger[]
     */
    public function get_exponents(): array
    {
        return $this->exponents;
    }
    public function get_coefficient(): ?Big_Integer
    {
        return $this->coefficient;
    }
    public function is_public(): bool
    {
        return !array_key_exists('d', $this->values);
    }
    public static function to_public(self $private): self
    {
        $data = $private->to_array();
        $keys = ['p', 'd', 'q', 'dp', 'dq', 'qi'];
        foreach ($keys as $key) {
            if (array_key_exists($key, $data)) {
                unset($data[$key]);
            }
        }
        return new self(new JWK($data));
    }
    public function to_array(): array
    {
        return $this->values;
    }
    public function to_pem(): string
    {
        if (array_key_exists('d', $this->values)) {
            $this->sequence = Sequence::create(Integer::create(0), Rsa_Encryption_Algorithm_Identifier::create()->to_asn1(), Octet_String::create(Rsa_Private_Key::create($this->from_base64to_integer($this->values['n']), $this->from_base64to_integer($this->values['e']), $this->from_base64to_integer($this->values['d']), isset($this->values['p']) ? $this->from_base64to_integer($this->values['p']) : '0', isset($this->values['q']) ? $this->from_base64to_integer($this->values['q']) : '0', isset($this->values['dp']) ? $this->from_base64to_integer($this->values['dp']) : '0', isset($this->values['dq']) ? $this->from_base64to_integer($this->values['dq']) : '0', isset($this->values['qi']) ? $this->from_base64to_integer($this->values['qi']) : '0')->to_der()));
            return PEM::create(PEM::TYPE_PRIVATE_KEY, $this->sequence->to_der())->string();
        }
        $this->sequence = Sequence::create(Rsa_Encryption_Algorithm_Identifier::create()->to_asn1(), Bit_String::create(Rsa_Public_Key::create($this->from_base64to_integer($this->values['n']), $this->from_base64to_integer($this->values['e']))->to_der()));
        return PEM::create(PEM::TYPE_PUBLIC_KEY, $this->sequence->to_der())->string();
    }
    /**
     * Exponentiate with or without Chinese Remainder Theorem. Operation with primes 'p' and 'q' is appox. 2x faster.
     */
    public static function exponentiate(self $key, Big_Integer $c): Big_Integer
    {
        if ($c->compare(Big_Integer::create_from_decimal(0)) < 0 || $c->compare($key->get_modulus()) > 0) {
            throw new RuntimeException();
        }
        if ($key->is_public() || $key->get_coefficient() === null || count($key->get_primes()) === 0 || count($key->get_exponents()) === 0) {
            return $c->mod_pow($key->get_exponent(), $key->get_modulus());
        }
        $p = $key->get_primes()[0];
        $q = $key->get_primes()[1];
        $d_p = $key->get_exponents()[0];
        $d_q = $key->get_exponents()[1];
        $q_inv = $key->get_coefficient();
        $m1 = $c->mod_pow($d_p, $p);
        $m2 = $c->mod_pow($d_q, $q);
        $h = $q_inv->multiply($m1->subtract($m2)->add($p))->mod($p);
        return $m2->add($h->multiply($q));
    }
    private function populate_big_integers(): void
    {
        $this->modulus = $this->convert_base64string_to_big_integer($this->values['n']);
        $this->modulus_length = strlen($this->get_modulus()->to_bytes());
        $this->public_exponent = $this->convert_base64string_to_big_integer($this->values['e']);
        if (!$this->is_public()) {
            $this->private_exponent = $this->convert_base64string_to_big_integer($this->values['d']);
            if (array_key_exists('p', $this->values) && array_key_exists('q', $this->values)) {
                $this->primes = [$this->convert_base64string_to_big_integer($this->values['p']), $this->convert_base64string_to_big_integer($this->values['q'])];
                if (array_key_exists('dp', $this->values) && array_key_exists('dq', $this->values) && array_key_exists('qi', $this->values)) {
                    $this->exponents = [$this->convert_base64string_to_big_integer($this->values['dp']), $this->convert_base64string_to_big_integer($this->values['dq'])];
                    $this->coefficient = $this->convert_base64string_to_big_integer($this->values['qi']);
                }
            }
        }
    }
    private function convert_base64string_to_big_integer(string $value): Big_Integer
    {
        return Big_Integer::create_from_binary_string(Base64url_Safe::decode_no_padding($value));
    }
    private function from_base64to_integer(string $value): string
    {
        $unpacked = unpack('H*', Base64url_Safe::decode_no_padding($value));
        if (!is_array($unpacked) || count($unpacked) === 0) {
            throw new InvalidArgumentException('Unable to get the private key');
        }
        return \Brick\Math\Big_Integer::from_base(current($unpacked), 16)->to_base(10);
    }
}