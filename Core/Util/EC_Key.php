<?php

declare (strict_types=1);
namespace Jose\Component\Core\Util;

use function extension_loaded;
use InvalidArgumentException;
use function is_array;
use function is_string;
use Jose\Component\Core\JWK;
use const OPENSSL_KEYTYPE_EC;
use RuntimeException;
use function sprintf;
use const STR_PAD_LEFT;
/**
 * @internal
 */
final readonly class Ec_Key
{
    public static function convert_to_pem(JWK $jwk): string
    {
        if ($jwk->has('d')) {
            return self::convert_private_key_to_pem($jwk);
        }
        return self::convert_public_key_to_pem($jwk);
    }
    public static function convert_public_key_to_pem(JWK $jwk): string
    {
        $der = match ($jwk->get('crv')) {
            'P-256' => self::p256public_key(),
            'secp256k1' => self::p256k_public_key(),
            'P-384' => self::p384public_key(),
            'P-521' => self::p521public_key(),
            default => throw new InvalidArgumentException('Unsupported curve.'),
        };
        $der .= self::get_key($jwk);
        $pem = '-----BEGIN PUBLIC KEY-----' . "\n";
        $pem .= chunk_split(base64_encode($der), 64, "\n");
        return $pem . ('-----END PUBLIC KEY-----' . "\n");
    }
    public static function convert_private_key_to_pem(JWK $jwk): string
    {
        $der = match ($jwk->get('crv')) {
            'P-256' => self::p256private_key($jwk),
            'secp256k1' => self::p256k_private_key($jwk),
            'P-384' => self::p384private_key($jwk),
            'P-521' => self::p521private_key($jwk),
            default => throw new InvalidArgumentException('Unsupported curve.'),
        };
        $der .= self::get_key($jwk);
        $pem = '-----BEGIN EC PRIVATE KEY-----' . "\n";
        $pem .= chunk_split(base64_encode($der), 64, "\n");
        return $pem . ('-----END EC PRIVATE KEY-----' . "\n");
    }
    /**
     * Creates a EC key with the given curve and additional values.
     *
     * @param string $curve The curve
     * @param array $values values to configure the key
     */
    public static function create_ec_key(string $curve, array $values = []): JWK
    {
        $jwk = self::create_ec_key_using_open_ssl($curve);
        $values = array_merge($values, $jwk);
        return new JWK($values);
    }
    private static function get_nist_curve_size(string $curve): int
    {
        return match ($curve) {
            'P-256', 'secp256k1' => 256,
            'P-384' => 384,
            'P-521' => 521,
            default => throw new InvalidArgumentException(sprintf('The curve "%s" is not supported.', $curve)),
        };
    }
    private static function create_ec_key_using_open_ssl(string $curve): array
    {
        if (!extension_loaded('openssl')) {
            throw new RuntimeException('Please install the OpenSSL extension');
        }
        $key = openssl_pkey_new(['curve_name' => self::get_openssl_curve_name($curve), 'private_key_type' => OPENSSL_KEYTYPE_EC, 'private_key_bits' => 2048]);
        if ($key === false) {
            throw new RuntimeException('Unable to create the key');
        }
        $result = openssl_pkey_export($key, $out);
        if ($result === false) {
            throw new RuntimeException('Unable to create the key');
        }
        $res = openssl_pkey_get_private($out);
        if ($res === false) {
            throw new RuntimeException('Unable to create the key');
        }
        $details = openssl_pkey_get_details($res);
        if ($details === false) {
            throw new InvalidArgumentException('Unable to get the key details');
        }
        $nist_curve_size = self::get_nist_curve_size($curve);
        return ['kty' => 'EC', 'crv' => $curve, 'd' => Base64url_Safe::encode_unpadded(str_pad((string) $details['ec']['d'], (int) ceil($nist_curve_size / 8), "\x00", STR_PAD_LEFT)), 'x' => Base64url_Safe::encode_unpadded(str_pad((string) $details['ec']['x'], (int) ceil($nist_curve_size / 8), "\x00", STR_PAD_LEFT)), 'y' => Base64url_Safe::encode_unpadded(str_pad((string) $details['ec']['y'], (int) ceil($nist_curve_size / 8), "\x00", STR_PAD_LEFT))];
    }
    private static function get_openssl_curve_name(string $curve): string
    {
        return match ($curve) {
            'P-256' => 'prime256v1',
            'secp256k1' => 'secp256k1',
            'P-384' => 'secp384r1',
            'P-521' => 'secp521r1',
            default => throw new InvalidArgumentException(sprintf('The curve "%s" is not supported.', $curve)),
        };
    }
    private static function p256public_key(): string
    {
        return pack('H*', '3059' . '3013' . '0607' . '2a8648ce3d0201' . '0608' . '2a8648ce3d030107' . '0342' . '00');
    }
    private static function p256k_public_key(): string
    {
        return pack('H*', '3056' . '3010' . '0607' . '2a8648ce3d0201' . '0605' . '2B8104000A' . '0342' . '00');
    }
    private static function p384public_key(): string
    {
        return pack('H*', '3076' . '3010' . '0607' . '2a8648ce3d0201' . '0605' . '2b81040022' . '0362' . '00');
    }
    private static function p521public_key(): string
    {
        return pack('H*', '30819b' . '3010' . '0607' . '2a8648ce3d0201' . '0605' . '2b81040023' . '038186' . '00');
    }
    private static function p256private_key(JWK $jwk): string
    {
        $d = $jwk->get('d');
        if (!is_string($d)) {
            throw new InvalidArgumentException('Unable to get the private key');
        }
        $d = unpack('H*', str_pad(Base64url_Safe::decode_no_padding($d), 32, "\x00", STR_PAD_LEFT));
        if (!is_array($d) || !isset($d[1])) {
            throw new InvalidArgumentException('Unable to get the private key');
        }
        return pack('H*', '3077' . '020101' . '0420' . $d[1] . 'a00a' . '0608' . '2a8648ce3d030107' . 'a144' . '0342' . '00');
    }
    private static function p256k_private_key(JWK $jwk): string
    {
        $d = $jwk->get('d');
        if (!is_string($d)) {
            throw new InvalidArgumentException('Unable to get the private key');
        }
        $d = unpack('H*', str_pad(Base64url_Safe::decode_no_padding($d), 32, "\x00", STR_PAD_LEFT));
        if (!is_array($d) || !isset($d[1])) {
            throw new InvalidArgumentException('Unable to get the private key');
        }
        return pack('H*', '3074' . '020101' . '0420' . $d[1] . 'a007' . '0605' . '2b8104000a' . 'a144' . '0342' . '00');
    }
    private static function p384private_key(JWK $jwk): string
    {
        $d = $jwk->get('d');
        if (!is_string($d)) {
            throw new InvalidArgumentException('Unable to get the private key');
        }
        $d = unpack('H*', str_pad(Base64url_Safe::decode_no_padding($d), 48, "\x00", STR_PAD_LEFT));
        if (!is_array($d) || !isset($d[1])) {
            throw new InvalidArgumentException('Unable to get the private key');
        }
        return pack('H*', '3081a4' . '020101' . '0430' . $d[1] . 'a007' . '0605' . '2b81040022' . 'a164' . '0362' . '00');
    }
    private static function p521private_key(JWK $jwk): string
    {
        $d = $jwk->get('d');
        if (!is_string($d)) {
            throw new InvalidArgumentException('Unable to get the private key');
        }
        $d = unpack('H*', str_pad(Base64url_Safe::decode_no_padding($d), 66, "\x00", STR_PAD_LEFT));
        if (!is_array($d) || !isset($d[1])) {
            throw new InvalidArgumentException('Unable to get the private key');
        }
        return pack('H*', '3081dc' . '020101' . '0442' . $d[1] . 'a007' . '0605' . '2b81040023' . 'a18189' . '038186' . '00');
    }
    private static function get_key(JWK $jwk): string
    {
        $crv = $jwk->get('crv');
        if (!is_string($crv)) {
            throw new InvalidArgumentException('Unable to get the curve');
        }
        $nist_curve_size = self::get_nist_curve_size($crv);
        $length = (int) ceil($nist_curve_size / 8);
        $x = $jwk->get('x');
        if (!is_string($x)) {
            throw new InvalidArgumentException('Unable to get the public key');
        }
        $y = $jwk->get('y');
        if (!is_string($y)) {
            throw new InvalidArgumentException('Unable to get the public key');
        }
        $bin_x = ltrim(Base64url_Safe::decode_no_padding($x), "\x00");
        $bin_y = ltrim(Base64url_Safe::decode_no_padding($y), "\x00");
        return "\x04" . str_pad($bin_x, $length, "\x00", STR_PAD_LEFT) . str_pad($bin_y, $length, "\x00", STR_PAD_LEFT);
    }
}