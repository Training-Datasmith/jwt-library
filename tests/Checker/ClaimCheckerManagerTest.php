<?php

declare(strict_types=1);

namespace Jose\Tests\Checker;

use Jose\Component\Checker\AudienceChecker;
use Jose\Component\Checker\CallableChecker;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\InvalidClaimException;
use Jose\Component\Checker\IssuedAtChecker;
use Jose\Component\Checker\IsEqualChecker;
use Jose\Component\Checker\IssuerChecker;
use Jose\Component\Checker\MissingMandatoryClaimException;
use Jose\Component\Checker\NotBeforeChecker;
use Jose\Tests\Support\FixedClock;
use PHPUnit\Framework\TestCase;

final class ClaimCheckerManagerTest extends TestCase
{
    private const NOW = 1767225600;

    private function clock(): FixedClock
    {
        return new FixedClock(new \DateTimeImmutable('@' . self::NOW));
    }

    public function testExpirationChecker(): void
    {
        $checker = new ExpirationTimeChecker($this->clock());
        $checker->checkClaim(self::NOW + 60);
        $this->expectException(InvalidClaimException::class);
        $checker->checkClaim(self::NOW - 60);
    }

    public function testExpirationDrift(): void
    {
        $checker = new ExpirationTimeChecker($this->clock(), 30);
        $checker->checkClaim(self::NOW - 20);
        $this->expectException(InvalidClaimException::class);
        $checker->checkClaim(self::NOW - 40);
    }

    public function testNotBeforeChecker(): void
    {
        $checker = new NotBeforeChecker($this->clock());
        $checker->checkClaim(self::NOW - 10);
        $this->expectException(InvalidClaimException::class);
        $checker->checkClaim(self::NOW + 60);
    }

    public function testIssuedAtChecker(): void
    {
        $checker = new IssuedAtChecker($this->clock());
        $checker->checkClaim(self::NOW);
        $this->expectException(InvalidClaimException::class);
        $checker->checkClaim(self::NOW + 60);
    }

    public function testAudienceChecker(): void
    {
        $checker = new AudienceChecker('api');
        $checker->checkClaim('api');
        $checker->checkClaim(['other', 'api']);
        $this->expectException(InvalidClaimException::class);
        $checker->checkClaim('wrong');
    }

    public function testIssuerChecker(): void
    {
        $checker = new IssuerChecker(['https://issuer.test']);
        $checker->checkClaim('https://issuer.test');
        $this->expectException(InvalidClaimException::class);
        $checker->checkClaim('https://other.test');
    }

    public function testIsEqualAndCallable(): void
    {
        (new IsEqualChecker('sub', 'user-1'))->checkClaim('user-1');
        (new CallableChecker('role', static fn (mixed $v): bool => $v === 'admin'))->checkClaim('admin');
        $this->expectException(InvalidClaimException::class);
        (new IsEqualChecker('sub', 'user-1'))->checkClaim('x');
    }

    public function testCallableConstructorRejectsNonCallable(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new CallableChecker('x', 'not-callable');
    }

    public function testManagerMandatoryAndReturn(): void
    {
        $mgr = new ClaimCheckerManager([
            new ExpirationTimeChecker($this->clock()),
            new IsEqualChecker('sub', 'alice'),
        ]);
        try {
            $mgr->check(['sub' => 'alice'], ['iss']);
            self::fail('expected missing mandatory');
        } catch (MissingMandatoryClaimException $e) {
            self::assertContains('iss', $e->getClaims());
        }
        $checked = $mgr->check(['sub' => 'alice', 'exp' => self::NOW + 60, 'extra' => 1]);
        self::assertArrayHasKey('sub', $checked);
        self::assertArrayHasKey('exp', $checked);
        self::assertArrayNotHasKey('extra', $checked);
    }
}
