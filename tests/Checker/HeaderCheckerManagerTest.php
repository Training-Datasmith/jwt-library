<?php

declare(strict_types=1);

namespace Jose\Tests\Checker;

use InvalidArgumentException;
use Jose\Component\Checker\AlgorithmChecker;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Checker\HeaderCheckerManagerFactory;
use Jose\Component\Checker\InvalidHeaderException;
use Jose\Component\Checker\IsEqualChecker;
use Jose\Component\Checker\MissingMandatoryHeaderParameterException;
use Jose\Component\Checker\UnencodedPayloadChecker;
use Jose\Component\Encryption\JWE;
use Jose\Component\Encryption\JWETokenSupport;
use Jose\Component\Encryption\Recipient;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSTokenSupport;
use PHPUnit\Framework\TestCase;

final class HeaderCheckerManagerTest extends TestCase
{
    public function testAlgorithmChecker(): void
    {
        $checker = new AlgorithmChecker(['HS256']);
        $checker->checkHeader('HS256');
        $this->expectException(InvalidHeaderException::class);
        $checker->checkHeader('none');
    }

    public function testUnencodedPayloadChecker(): void
    {
        $checker = new UnencodedPayloadChecker();
        self::assertTrue($checker->protectedHeaderOnly());
        $checker->checkHeader(true);
        $this->expectException(InvalidHeaderException::class);
        $checker->checkHeader(1);
    }

    public function testJwsHeaderRules(): void
    {
        $mgr = new HeaderCheckerManager([new AlgorithmChecker(['HS256'])], [new JWSTokenSupport()]);
        $jws = new JWS('p', 'c', false);
        $jws = $jws->addSignature('sig', ['alg' => 'HS256'], 'enc');
        $mgr->check($jws, 0);
        $bad = $jws->addSignature('sig2', ['alg' => 'HS256'], 'enc', ['alg' => 'HS256']);
        $this->expectException(InvalidArgumentException::class);
        $mgr->check($bad, 1);
    }

    public function testMandatoryAndCritical(): void
    {
        $mgr = new HeaderCheckerManager([
            new AlgorithmChecker(['HS256']),
            new IsEqualChecker('kid', '1', true),
        ], [new JWSTokenSupport()]);
        $jws = (new JWS('p', 'c', false))->addSignature('s', ['alg' => 'HS256', 'crit' => ['alg']], 'enc');
        $mgr->check($jws, 0);
        $this->expectException(MissingMandatoryHeaderParameterException::class);
        $mgr->check($jws, 0, ['kid']);
    }

    public function testJweTokenSupport(): void
    {
        $mgr = new HeaderCheckerManager([new AlgorithmChecker(['dir'])], [new JWETokenSupport()]);
        $jwe = new JWE('ct', 'iv', 'tag', null, [], ['alg' => 'dir', 'enc' => 'A128GCM'], 'enc', [new Recipient([], null)]);
        $mgr->check($jwe, 0);
        $this->expectException(InvalidArgumentException::class);
        (new HeaderCheckerManager([new AlgorithmChecker(['HS256'])], [new JWSTokenSupport()]))->check($jwe, 0);
    }

    public function testFactoryUnknownAlias(): void
    {
        $factory = new HeaderCheckerManagerFactory();
        $factory->add('alg', new AlgorithmChecker(['HS256']));
        $factory->create(['alg']);
        $this->expectException(InvalidArgumentException::class);
        $factory->create(['missing']);
    }
}
