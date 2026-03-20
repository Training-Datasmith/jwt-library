<?php

declare (strict_types=1);
namespace Jose\Component\Core\Util;

use InvalidArgumentException;
use function is_string;
use const STR_PAD_LEFT;
use function strlen;
/**
 * @internal
 */
final readonly class Ec_Signature
{
    private const ASN1_SEQUENCE = '30';
    private const ASN1_INTEGER = '02';
    private const ASN1_MAX_SINGLE_BYTE = 128;
    private const ASN1_LENGTH_2BYTES = '81';
    private const ASN1_BIG_INTEGER_LIMIT = '7f';
    private const ASN1_NEGATIVE_INTEGER = '00';
    private const BYTE_SIZE = 2;
    public static function to_asn1(string $signature, int $length): string
    {
        $signature = bin2hex($signature);
        if (self::octet_length($signature) !== $length) {
            throw new InvalidArgumentException('Invalid signature length.');
        }
        $point_r = self::prepare_positive_integer(substr($signature, 0, $length));
        $point_s = self::prepare_positive_integer(substr($signature, $length));
        $length_r = self::octet_length($point_r);
        $length_s = self::octet_length($point_s);
        $total_length = $length_r + $length_s + self::BYTE_SIZE + self::BYTE_SIZE;
        $length_prefix = $total_length > self::ASN1_MAX_SINGLE_BYTE ? self::ASN1_LENGTH_2BYTES : '';
        $bin = hex2bin(self::ASN1_SEQUENCE . $length_prefix . dechex($total_length) . self::ASN1_INTEGER . dechex($length_r) . $point_r . self::ASN1_INTEGER . dechex($length_s) . $point_s);
        if (!is_string($bin)) {
            throw new InvalidArgumentException('Unable to parse the data');
        }
        return $bin;
    }
    public static function from_asn1(string $signature, int $length): string
    {
        $message = bin2hex($signature);
        $position = 0;
        if (self::read_asn1content($message, $position, self::BYTE_SIZE) !== self::ASN1_SEQUENCE) {
            throw new InvalidArgumentException('Invalid data. Should start with a sequence.');
        }
        if (self::read_asn1content($message, $position, self::BYTE_SIZE) === self::ASN1_LENGTH_2BYTES) {
            $position += self::BYTE_SIZE;
        }
        $point_r = self::retrieve_positive_integer(self::read_asn1integer($message, $position));
        $point_s = self::retrieve_positive_integer(self::read_asn1integer($message, $position));
        $bin = hex2bin(str_pad($point_r, $length, '0', STR_PAD_LEFT) . str_pad($point_s, $length, '0', STR_PAD_LEFT));
        if (!is_string($bin)) {
            throw new InvalidArgumentException('Unable to parse the data');
        }
        return $bin;
    }
    private static function octet_length(string $data): int
    {
        return (int) (strlen($data) / self::BYTE_SIZE);
    }
    private static function prepare_positive_integer(string $data): string
    {
        if (substr($data, 0, self::BYTE_SIZE) > self::ASN1_BIG_INTEGER_LIMIT) {
            return self::ASN1_NEGATIVE_INTEGER . $data;
        }
        while (str_starts_with($data, self::ASN1_NEGATIVE_INTEGER) && substr($data, 2, self::BYTE_SIZE) <= self::ASN1_BIG_INTEGER_LIMIT) {
            $data = substr($data, 2);
        }
        return $data;
    }
    private static function read_asn1content(string $message, int &$position, int $length): string
    {
        $content = substr($message, $position, $length);
        $position += $length;
        return $content;
    }
    private static function read_asn1integer(string $message, int &$position): string
    {
        if (self::read_asn1content($message, $position, self::BYTE_SIZE) !== self::ASN1_INTEGER) {
            throw new InvalidArgumentException('Invalid data. Should contain an integer.');
        }
        $length = (int) hexdec(self::read_asn1content($message, $position, self::BYTE_SIZE));
        return self::read_asn1content($message, $position, $length * self::BYTE_SIZE);
    }
    private static function retrieve_positive_integer(string $data): string
    {
        while (str_starts_with($data, self::ASN1_NEGATIVE_INTEGER) && substr($data, 2, self::BYTE_SIZE) > self::ASN1_BIG_INTEGER_LIMIT) {
            $data = substr($data, 2);
        }
        return $data;
    }
}