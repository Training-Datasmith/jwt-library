<?php

declare(strict_types=1);

namespace Jose\Tests\KeyManagement;

use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\KeyManagement\Analyzer\AlgorithmAnalyzer;
use Jose\Component\KeyManagement\Analyzer\KeyAnalyzerManager;
use Jose\Component\KeyManagement\Analyzer\KeyIdentifierAnalyzer;
use Jose\Component\KeyManagement\Analyzer\Message;
use Jose\Component\KeyManagement\Analyzer\NoneAnalyzer;
use Jose\Component\KeyManagement\Analyzer\OctAnalyzer;
use Jose\Component\KeyManagement\Analyzer\RsaAnalyzer;
use Jose\Component\KeyManagement\Analyzer\UsageAnalyzer;
use Jose\Component\KeyManagement\JWKFactory;
use PHPUnit\Framework\TestCase;

final class AnalyzerTest extends TestCase
{
    public function testUsageAnalyzer(): void
    {
        $bag = new \Jose\Component\KeyManagement\Analyzer\MessageBag();
        (new UsageAnalyzer())->analyze(new JWK(['kty' => 'oct', 'k' => 'AA']), $bag);
        self::assertGreaterThan(0, count($bag));
        $bag2 = new \Jose\Component\KeyManagement\Analyzer\MessageBag();
        (new UsageAnalyzer())->analyze(new JWK(['kty' => 'oct', 'use' => 'foo', 'k' => 'AA']), $bag2);
        self::assertSame(Message::SEVERITY_HIGH, $bag2->all()[0]->getSeverity());
    }

    public function testOctAndRsaAnalyzers(): void
    {
        $short = new JWK(['kty' => 'oct', 'k' => Base64UrlSafe::encodeUnpadded("\x01\x02")]);
        $bag = new \Jose\Component\KeyManagement\Analyzer\MessageBag();
        (new OctAnalyzer())->analyze($short, $bag);
        self::assertNotEmpty($bag->all());
        $rsa = JWKFactory::createRSAKey(1024);
        $bag2 = new \Jose\Component\KeyManagement\Analyzer\MessageBag();
        (new RsaAnalyzer())->analyze($rsa, $bag2);
        self::assertNotEmpty($bag2->all());
    }

    public function testNoneAndMetaAnalyzers(): void
    {
        $bag = new \Jose\Component\KeyManagement\Analyzer\MessageBag();
        (new NoneAnalyzer())->analyze(JWKFactory::createNoneKey(), $bag);
        self::assertNotEmpty($bag->all());
        $octBag = new \Jose\Component\KeyManagement\Analyzer\MessageBag();
        (new NoneAnalyzer())->analyze(new JWK(['kty' => 'oct', 'k' => 'AA']), $octBag);
        self::assertEmpty($octBag->all());
        $meta = new \Jose\Component\KeyManagement\Analyzer\MessageBag();
        (new KeyIdentifierAnalyzer())->analyze(new JWK(['kty' => 'oct', 'k' => 'AA']), $meta);
        (new AlgorithmAnalyzer())->analyze(new JWK(['kty' => 'oct', 'k' => 'AA']), $meta);
        self::assertGreaterThanOrEqual(2, count($meta->all()));
    }

    public function testKeyAnalyzerManagerRunsAll(): void
    {
        $mgr = new KeyAnalyzerManager();
        $mgr->add(new KeyIdentifierAnalyzer());
        $mgr->add(new AlgorithmAnalyzer());
        self::assertGreaterThanOrEqual(2, count($mgr->analyze(new JWK(['kty' => 'oct', 'k' => 'AA']))->all()));
    }
}
