<?php

declare (strict_types=1);
namespace Jose\Component\Core\Util;

use function extension_loaded;
use InvalidArgumentException;
use function pack;
use RangeException;
use function rtrim;
use Sensitive_Parameter;
use function sodium_base642bin;
use const SODIUM_BASE64_VARIANT_URLSAFE;
use const SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING;
use function sodium_bin2base64;
use Sodium_Exception;
use function strlen;
use function substr;
use function unpack;
/**
 *  Copyright (c) 2016 - 2022 Paragon Initiative Enterprises.
 *  Copyright (c) 2014 Steve "Sc00bz" Thomas (steve at tobtu dot com)
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in all
 *  copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
 */
final readonly class Base64url_Safe
{
    public static function encode(
        #[Sensitive_Parameter]
        string $bin_string
    ): string
    {
        if (extension_loaded('sodium')) {
            try {
                return sodium_bin2base64($bin_string, SODIUM_BASE64_VARIANT_URLSAFE);
            } catch (Sodium_Exception $ex) {
                throw new RangeException($ex->get_message(), $ex->get_code(), $ex);
            }
        }
        return static::do_encode($bin_string, true);
    }
    public static function encode_unpadded(
        #[Sensitive_Parameter]
        string $src
    ): string
    {
        if (extension_loaded('sodium')) {
            try {
                return sodium_bin2base64($src, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
            } catch (Sodium_Exception $ex) {
                throw new RangeException($ex->get_message(), $ex->get_code(), $ex);
            }
        }
        return static::do_encode($src, false);
    }
    public static function decode(
        #[Sensitive_Parameter]
        string $encoded_string,
        bool $strict_padding = false
    ): string
    {
        $src_len = self::safe_strlen($encoded_string);
        if ($src_len === 0) {
            return '';
        }
        if ($strict_padding) {
            if (($src_len & 3) === 0) {
                if ($encoded_string[$src_len - 1] === '=') {
                    $src_len--;
                    if ($encoded_string[$src_len - 1] === '=') {
                        $src_len--;
                    }
                }
            }
            if (($src_len & 3) === 1) {
                throw new RangeException('Incorrect padding');
            }
            if ($encoded_string[$src_len - 1] === '=') {
                throw new RangeException('Incorrect padding');
            }
            if (extension_loaded('sodium')) {
                try {
                    return sodium_base642bin(self::safe_substr($encoded_string, 0, $src_len), SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
                } catch (Sodium_Exception $ex) {
                    throw new RangeException($ex->get_message(), $ex->get_code(), $ex);
                }
            }
        } else {
            $encoded_string = rtrim($encoded_string, '=');
            $src_len = self::safe_strlen($encoded_string);
        }
        $err = 0;
        $dest = '';
        for ($i = 0; $i + 4 <= $src_len; $i += 4) {
            /** @var array<int, int> $chunk */
            $chunk = unpack('C*', self::safe_substr($encoded_string, $i, 4));
            $c0 = static::decode6Bits($chunk[1]);
            $c1 = static::decode6Bits($chunk[2]);
            $c2 = static::decode6Bits($chunk[3]);
            $c3 = static::decode6Bits($chunk[4]);
            $dest .= pack('CCC', ($c0 << 2 | $c1 >> 4) & 0xff, ($c1 << 4 | $c2 >> 2) & 0xff, ($c2 << 6 | $c3) & 0xff);
            $err |= ($c0 | $c1 | $c2 | $c3) >> 8;
        }
        if ($i < $src_len) {
            /** @var array<int, int> $chunk */
            $chunk = unpack('C*', self::safe_substr($encoded_string, $i, $src_len - $i));
            $c0 = static::decode6Bits($chunk[1]);
            if ($i + 2 < $src_len) {
                $c1 = static::decode6Bits($chunk[2]);
                $c2 = static::decode6Bits($chunk[3]);
                $dest .= pack('CC', ($c0 << 2 | $c1 >> 4) & 0xff, ($c1 << 4 | $c2 >> 2) & 0xff);
                $err |= ($c0 | $c1 | $c2) >> 8;
                if ($strict_padding) {
                    $err |= $c2 << 6 & 0xff;
                }
            } elseif ($i + 1 < $src_len) {
                $c1 = static::decode6Bits($chunk[2]);
                $dest .= pack('C', ($c0 << 2 | $c1 >> 4) & 0xff);
                $err |= ($c0 | $c1) >> 8;
                if ($strict_padding) {
                    $err |= $c1 << 4 & 0xff;
                }
            } elseif ($strict_padding) {
                $err |= 1;
            }
        }
        $check = $err === 0;
        if (!$check) {
            throw new RangeException('Base64::decode() only expects characters in the correct base64 alphabet');
        }
        return $dest;
    }
    public static function decode_no_padding(
        #[Sensitive_Parameter]
        string $encoded_string
    ): string
    {
        $src_len = self::safe_strlen($encoded_string);
        if ($src_len === 0) {
            return '';
        }
        if (($src_len & 3) === 0) {
            if ($encoded_string[$src_len - 1] === '=' || $encoded_string[$src_len - 2] === '=') {
                throw new InvalidArgumentException("decodeNoPadding() doesn't tolerate padding");
            }
        }
        return static::decode($encoded_string, true);
    }
    private static function do_encode(
        #[Sensitive_Parameter]
        string $src,
        bool $pad = true
    ): string
    {
        $dest = '';
        $src_len = self::safe_strlen($src);
        for ($i = 0; $i + 3 <= $src_len; $i += 3) {
            /** @var array<int, int> $chunk */
            $chunk = unpack('C*', self::safe_substr($src, $i, 3));
            $b0 = $chunk[1];
            $b1 = $chunk[2];
            $b2 = $chunk[3];
            $dest .= static::encode6Bits($b0 >> 2) . static::encode6Bits(($b0 << 4 | $b1 >> 4) & 63) . static::encode6Bits(($b1 << 2 | $b2 >> 6) & 63) . static::encode6Bits($b2 & 63);
        }
        if ($i < $src_len) {
            /** @var array<int, int> $chunk */
            $chunk = unpack('C*', self::safe_substr($src, $i, $src_len - $i));
            $b0 = $chunk[1];
            if ($i + 1 < $src_len) {
                $b1 = $chunk[2];
                $dest .= static::encode6Bits($b0 >> 2) . static::encode6Bits(($b0 << 4 | $b1 >> 4) & 63) . static::encode6Bits($b1 << 2 & 63);
                if ($pad) {
                    $dest .= '=';
                }
            } else {
                $dest .= static::encode6Bits($b0 >> 2) . static::encode6Bits($b0 << 4 & 63);
                if ($pad) {
                    $dest .= '==';
                }
            }
        }
        return $dest;
    }
    private static function decode6Bits(int $src): int
    {
        $ret = -1;
        $ret += (0x40 - $src & $src - 0x5b) >> 8 & $src - 64;
        $ret += (0x60 - $src & $src - 0x7b) >> 8 & $src - 70;
        $ret += (0x2f - $src & $src - 0x3a) >> 8 & $src + 5;
        $ret += (0x2c - $src & $src - 0x2e) >> 8 & 63;
        return $ret + ((0x5e - $src & $src - 0x60) >> 8 & 64);
    }
    private static function encode6Bits(int $src): string
    {
        $diff = 0x41;
        $diff += 25 - $src >> 8 & 6;
        $diff -= 51 - $src >> 8 & 75;
        $diff -= 61 - $src >> 8 & 13;
        $diff += 62 - $src >> 8 & 49;
        return pack('C', $src + $diff);
    }
    private static function safe_strlen(
        #[Sensitive_Parameter]
        string $str
    ): int
    {
        return strlen($str);
    }
    private static function safe_substr(
        #[Sensitive_Parameter]
        string $str,
        int $start = 0,
        $length = null
    ): string
    {
        if ($length === 0) {
            return '';
        }
        return substr($str, $start, $length);
    }
}