<?php

declare(strict_types=1);

namespace Jose\Tests\Support;

use Jose\Component\Core\JWK;

/**
 * Fixed ECDH-SS+A128KW / A128GCM compact JWE. Receiver: RFC 7518 Appendix C consumer (Bob) P-256 key.
 * Sender: static P-256 key from jwt-framework's ECDH-SS tests (not from RFC 7518).
 * (sender private + receiver public at encrypt; decrypt uses sender public + receiver private).
 */
final class EcdhSsA128KwJweFixture
{
    public const PAYLOAD = 'allow-list-positive';

    /**
     * Serialized once from fixed keys; all allow-list tests must unserialize this string.
     */
    public const COMPACT_TOKEN = 'eyJhbGciOiJFQ0RILVNTK0ExMjhLVyIsImVuYyI6IkExMjhHQ00ifQ.6ftbVfhjD0vtnlN4zzGbgqu5gQGOjjSC.6ii-Db_1bCeT9Q_k.idyHDZOlgA-DK3kVBcyYYGx9DA.6iZHBgtg3mILEvv2uyTw1Q';

    public static function senderPrivateKey(): JWK
    {
        return new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'OSo9FXcQCqDR6G3INwuMZn9_StSV6eLKn1KQIWufuyA',
            'y' => 'c4v6g44omMI_949wkYtJSG_pOyhyqqqJ7zqqdv5vwGU',
            'd' => 'xBRebaWQIa9DAxChfcOGDnfM39RMILisUxW16XHVN7c',
        ]);
    }

    public static function receiverPrivateKey(): JWK
    {
        return new JWK([
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
            'y' => 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
            'd' => 'VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw',
        ]);
    }
}
